// Chain reorganisation safety.
//
// QMS makes blocks by proof-of-(useful-)work and has no finality layer yet, so a block can be replaced by a competing
// one. A transaction from a replaced block may come back in another block (at a different position), come back later,
// or never come back. Every Quantly transaction whose logs were processed is therefore remembered with the block it
// came from (indexed_txs). When that block is no longer on the chain, or the same transaction shows up from another
// block, everything it wrote is undone first and read again from the chain as it is now. So a sale is never counted
// twice, and a sale, mint, fee or transfer that did not survive never stays in the database.
//
// Nothing is undone on a single answer: the public RPC is load-balanced and one node can be a block behind or on a
// short-lived fork. A replaced block is confirmed with the transaction's own receipt, and a transaction that seems to
// have moved is only re-read when its new block is the one the chain has at that height.
import { many, one, q } from '../db.js';
import { ZERO_ADDRESS } from '../config.js';
import { collectionContract, getProvider } from '../lib/chain.js';
import { refreshCollectionStats } from '../lib/stats.js';

/** How far back (in blocks) transactions are re-checked: about 25 minutes at 10 s blocks. */
export const REORG_WINDOW = Number(process.env.INDEXER_REORG_WINDOW ?? 150);
/** Blocks checked per round, newest first (bounds RPC use). */
const BLOCKS_PER_ROUND = 60;
const lc = (v) => String(v || '').toLowerCase();

/** Goes up on every rollback in this process; the indexer clears its "already seen" cache when it changes. */
export let rollbackCount = 0;

let ready = null; // true, or the time the table was found missing (looked up again a minute later)
let warned = false;
async function tableReady() {
  if (ready === true) return true;
  if (typeof ready === 'number' && Date.now() - ready < 60_000) return false;
  const row = await one(`select to_regclass('indexed_txs') is not null as ok`).catch(() => null);
  if (row?.ok) {
    ready = true;
    return true;
  }
  ready = Date.now();
  if (!warned) {
    warned = true;
    console.warn('[reorg] table indexed_txs is missing: run backend/db/setup_all.sql to turn on reorg protection.');
  }
  return false;
}

/**
 * Called before a Quantly transaction's logs are processed. Returns false when they should be skipped.
 * If the same transaction was processed before from a different block, what it wrote then is undone first, but only
 * once the chain confirms the new block (otherwise the logs came from a node on a short-lived fork: skipped).
 */
export async function beginTx(txHash, blockNumber, blockHash) {
  if (!blockHash || !(await tableReady())) return true;
  const tx = lc(txHash);
  const at = lc(blockHash);
  const prev = await one(`select block_hash from indexed_txs where tx_hash = $1`, [tx]);
  if (prev && prev.block_hash !== at) {
    const block = await getProvider().getBlock(Number(blockNumber)).catch(() => null);
    if (lc(block?.hash) !== at) return false; // not the chain's block at that height (yet): keep what we have
    console.log(`[reorg] ${tx} moved from block ${prev.block_hash} to ${at}: undoing what it wrote before`);
    await rollbackTx(tx);
  }
  await q(
    `insert into indexed_txs (tx_hash, block_number, block_hash) values ($1,$2,$3)
     on conflict (tx_hash) do update set block_number = excluded.block_number, block_hash = excluded.block_hash`,
    [tx, Number(blockNumber), at],
  );
  return true;
}

/** Remembers a collection created by this transaction (logged if its creation does not survive). */
export async function noteCreatedCollection(txHash, address) {
  if (!(await tableReady())) return;
  await q(
    `update indexed_txs set created_collections = array_append(created_collections, $2)
     where tx_hash = $1 and not ($2 = any(created_collections))`,
    [lc(txHash), lc(address)],
  );
}

/** Owner of a token on the chain now; null if it does not exist. Any other error is thrown (the rollback is retried). */
async function ownerNow(collection, id) {
  try {
    return lc(await collectionContract(collection).ownerOf(id));
  } catch (e) {
    if (e?.code === 'CALL_EXCEPTION') return null; // the contract says this token does not exist
    // No contract at that address any more (its creation was undone, or the testnet was reset): the token does not
    // exist either. Without this, the empty answer fails to decode and the rollback would retry forever.
    const code = await getProvider().getCode(collection).catch(() => null);
    if (code === '0x') return null;
    throw e;
  }
}

/**
 * Undoes everything one transaction wrote, then re-reads the affected tokens from the chain. Idempotent: if it stops
 * half way (RPC error), the record stays and the next round runs it again.
 */
export async function rollbackTx(txHash) {
  const tx = lc(txHash);
  rollbackCount++;
  const acts = await many(`delete from activity where tx_hash = $1 returning type, collection, token_id::text as token_id`, [tx]);
  await q(`delete from fee_ledger where tx_hash = $1`, [tx]);
  await q(`delete from phase_changes where tx_hash = $1 or tx_hash like $2`, [tx, `${tx}:%`]);
  // Filled or cancelled by this transaction (one by one or by "cancel all"): open again until the chain says
  // otherwise. A copy of the transaction mined again is processed right after and sets it back.
  const orders = await many(
    `update orders set status = 'active', tx_hash = null, updated_at = now()
     where tx_hash = $1 and status in ('filled','cancelled') returning collection`,
    [tx],
  );
  const touched = new Set([...acts.map((a) => a.collection), ...orders.map((o) => o.collection)]);

  // Tokens this transaction minted, moved or sold: the owner is read from the chain as it is now.
  const tokens = new Map();
  for (const a of acts) if (a.token_id != null) tokens.set(`${a.collection}:${a.token_id}`, a);
  for (const { collection, token_id: id } of tokens.values()) {
    const owner = await ownerNow(collection, id);
    if (owner && owner !== ZERO_ADDRESS) {
      await q(`update tokens set owner = $3 where collection = $1 and token_id = $2`, [collection, id, owner]);
    } else {
      await q(`delete from tokens where collection = $1 and token_id = $2`, [collection, id]); // the mint did not survive
    }
    await q(
      `update tokens set last_sale_wei = (select price_wei from activity where type = 'sale' and collection = $1 and token_id = $2
                                         order by created_at desc, id desc limit 1)
       where collection = $1 and token_id = $2`,
      [collection, id],
    );
  }

  // A collection whose creation did not survive is never deleted here: its page, images and phase names belong to
  // the creator, and with CREATE2 the same creation usually lands again at the same address. It is only reported.
  const rec = await one(`select created_collections from indexed_txs where tx_hash = $1`, [tx]).catch(() => null);
  for (const address of rec?.created_collections || []) {
    const code = await getProvider().getCode(address).catch(() => null);
    if (code === '0x') console.warn(`[reorg] collection ${address}: its creation was undone by a reorg and is not on the chain (yet)`);
  }

  // Sales totals are added up as sales arrive, so they are recounted from what is left.
  if (touched.size) {
    await q(
      `update collections c set
         volume_wei = coalesce((select sum(price_wei) from activity a where a.collection = c.address and a.type = 'sale'), 0),
         sales_count = (select count(*) from activity a where a.collection = c.address and a.type = 'sale')
       where c.address = any($1)`,
      [[...touched]],
    );
    for (const c of touched) await refreshCollectionStats(c);
  }
  await q(`delete from indexed_txs where tx_hash = $1`, [tx]);
  return touched;
}

/**
 * Compares the recent blocks transactions were processed from with the chain, newest first. A transaction is undone
 * only when the chain has another block at that height AND its own receipt no longer points at the recorded block.
 * Returns the lowest replaced block number (the indexer reads again from there), or null.
 */
export async function checkReorgs(provider, head) {
  if (!(await tableReady())) return null;
  const rows = await many(
    `select tx_hash, block_number::int as n, block_hash from indexed_txs where block_number >= $1 order by block_number desc`,
    [Math.max(0, head - REORG_WINDOW)],
  );
  const byBlock = new Map();
  for (const r of rows) {
    if (!byBlock.has(r.n)) byBlock.set(r.n, []);
    byBlock.get(r.n).push(r);
  }
  let lowest = null;
  let checked = 0;
  for (const [n, txs] of byBlock) {
    if (++checked > BLOCKS_PER_ROUND) break; // the rest is checked next round
    // No answer, or "no such block" from a node a little behind: unknown, so nothing is undone.
    const block = await provider.getBlock(n).catch(() => null);
    if (!block?.hash) continue;
    const hash = lc(block.hash);
    for (const t of txs) {
      if (t.block_hash === hash) continue;
      // Ask the transaction itself: if its receipt still names the recorded block, the block answer came from a node
      // on a short-lived fork. An RPC error means unknown: checked again next round.
      let receipt;
      try {
        receipt = await provider.getTransactionReceipt(t.tx_hash);
      } catch {
        continue;
      }
      if (receipt && lc(receipt.blockHash) === t.block_hash) continue;
      console.log(`[reorg] block ${n} was replaced (${t.block_hash} → ${hash}): undoing ${t.tx_hash}`);
      try {
        await rollbackTx(t.tx_hash);
      } catch (e) {
        console.warn('[reorg] rollback stopped, will try again:', t.tx_hash, e.shortMessage || e.message);
        continue;
      }
      lowest = lowest === null ? n : Math.min(lowest, n);
    }
  }
  return lowest;
}

/** Drops records too old to be reorganised (keeps the table small). */
export async function pruneIndexedTxs(head) {
  if (!(await tableReady())) return;
  await q(`delete from indexed_txs where block_number < $1`, [Math.max(0, head - 50_000)]);
}
