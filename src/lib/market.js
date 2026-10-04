// Marketplace orders: EIP-712 hashing and validation against the contract itself.
import { TypedDataEncoder, concat, isAddress, keccak256, verifyTypedData } from 'ethers';
import { config } from '../config.js';
import { bad } from './http.js';
import { market } from './chain.js';

export const ORDER_TYPES = {
  Order: [
    { name: 'maker', type: 'address' },
    { name: 'side', type: 'uint8' },
    { name: 'collection', type: 'address' },
    { name: 'tokenId', type: 'uint256' },
    { name: 'anyToken', type: 'bool' },
    { name: 'price', type: 'uint256' },
    { name: 'maxFeeBps', type: 'uint16' },
    { name: 'maxRoyaltyBps', type: 'uint16' },
    { name: 'expiry', type: 'uint64' },
    { name: 'salt', type: 'uint256' },
    { name: 'counter', type: 'uint256' },
  ],
};

export const domain = () => ({ name: config.marketDomainName, version: '1', chainId: config.chainId, verifyingContract: config.market });

const STATUS = [
  'Fillable',
  'This order was already filled or cancelled',
  'This order has expired',
  'This order was cancelled (counter changed)',
  'The signature is not valid for this order',
  'This collection cannot be traded on this marketplace',
  'Price must be greater than 0',
  'The marketplace fee changed. Sign a new order.',
  'The creator royalty changed. Sign a new order.',
  'You do not own this item',
  'Approve the marketplace to transfer this collection first',
  'Not enough wrapped coin for this offer',
  'Approve the wrapped coin for the marketplace first',
  'The marketplace is paused',
  'Invalid order',
];

/** Normalises the JSON order from the browser into the exact typed-data values. */
export function normalizeOrder(o) {
  const need = ['maker', 'side', 'collection', 'tokenId', 'anyToken', 'price', 'maxFeeBps', 'maxRoyaltyBps', 'expiry', 'salt', 'counter'];
  if (!o || typeof o !== 'object' || need.some((k) => o[k] === undefined)) throw bad('Malformed order');
  if (!isAddress(o.maker) || !isAddress(o.collection)) throw bad('Malformed order address');
  const n = {
    maker: String(o.maker).toLowerCase(),
    side: Number(o.side),
    collection: String(o.collection).toLowerCase(),
    tokenId: BigInt(o.tokenId).toString(),
    anyToken: Boolean(o.anyToken),
    price: BigInt(o.price).toString(),
    maxFeeBps: Number(o.maxFeeBps),
    maxRoyaltyBps: Number(o.maxRoyaltyBps),
    expiry: BigInt(o.expiry).toString(),
    salt: BigInt(o.salt).toString(),
    counter: BigInt(o.counter).toString(),
  };
  if (![0, 1].includes(n.side)) throw bad('Invalid order side');
  if (n.side === 0 && n.anyToken) throw bad('Listings must be for one item');
  return n;
}

export const orderHash = (o) => TypedDataEncoder.hash(domain(), ORDER_TYPES, o).toLowerCase();

/** Checks an order with the marketplace contract (signature, counter, expiry, fees, ownership, approvals, wrapped-coin balance). */
export async function validateOrder(raw, signature) {
  if (!config.market) throw bad('Marketplace contract is not configured', 'not_ready');
  if (typeof signature !== 'string' || !/^0x[0-9a-fA-F]+$/.test(signature)) throw bad('Missing signature');
  const o = normalizeOrder(raw);
  const now = Math.floor(Date.now() / 1000);
  if (BigInt(o.price) <= 0n) throw bad('Price must be greater than 0');
  if (Number(o.expiry) <= now + 60) throw bad('Order expires too soon');
  if (Number(o.expiry) > now + 181 * 86400) throw bad('Orders can last at most 180 days');

  const hash = orderHash(o);
  const onchainHash = String(await market().hashOrder(toTuple(o))).toLowerCase();
  if (onchainHash !== hash) throw bad('Order hash mismatch (wrong chain or contract)');

  const status = Number(await market().checkOrder(toTuple(o), signature, o.anyToken ? 0 : o.tokenId, '0x0000000000000000000000000000000000000000'));
  if (status !== 0) throw bad(STATUS[status] || 'Order is not valid', `status_${status}`);
  return { order: o, hash };
}

export const toTuple = (o) => [o.maker, o.side, o.collection, o.tokenId, o.anyToken, o.price, o.maxFeeBps, o.maxRoyaltyBps, o.expiry, o.salt, o.counter];

/** EIP-712 struct hash of one order (what a bulk signature lists), same as the contract's orderStructHash. */
export const orderStructHash = (o) => TypedDataEncoder.hashStruct('Order', ORDER_TYPES, o).toLowerCase();

export const BULK_MAGIC = '5154424b';

/**
 * A bulk listing is signed as a binary tree of orders: BulkOrder(Order[2]...[2] tree) with 2, 4, ... 64 leaves. A list
 * that is not a power of two is filled up by repeating its last order (the same order, so it can only be filled
 * once). Buying one of them then needs only the path from that order to the root: at most 6 hashes, not every order.
 */
export function bulkTree(orders) {
  let height = 1;
  while (1 << height < orders.length) height++;
  const leaves = Array.from({ length: 1 << height }, (_, i) => orders[Math.min(i, orders.length - 1)]);
  let tree = leaves;
  while (tree.length > 2) tree = Array.from({ length: tree.length / 2 }, (_, i) => [tree[2 * i], tree[2 * i + 1]]);
  return { height, leaves, tree, types: { BulkOrder: [{ name: 'tree', type: `Order${'[2]'.repeat(height)}` }], Order: ORDER_TYPES.Order } };
}

/**
 * One signature for many listings: checks it really is the maker's signature over exactly these orders (the
 * wallet showed every one of them), then returns the per-order signature the contract expects:
 * marker | height | index | path to the root | the signature.
 */
export function bulkSignatures(orders, signature) {
  if (!Array.isArray(orders) || orders.length < 1 || orders.length > 50) throw bad('Send 1 to 50 orders');
  if (typeof signature !== 'string' || !/^0x[0-9a-fA-F]{130}$/.test(signature)) throw bad('Missing signature');
  const norm = orders.map(normalizeOrder);
  const maker = norm[0].maker;
  if (norm.some((o) => o.maker !== maker)) throw bad('All orders in one signature must be from the same wallet');
  const { height, leaves, tree, types } = bulkTree(norm);
  const signer = verifyTypedData(domain(), types, { tree }, signature).toLowerCase();
  if (signer !== maker) throw bad('The signature is not from this wallet');
  const levels = [leaves.map(orderStructHash)];
  while (levels.at(-1).length > 1) {
    const prev = levels.at(-1);
    levels.push(Array.from({ length: prev.length / 2 }, (_, i) => keccak256(concat([prev[2 * i], prev[2 * i + 1]]))));
  }
  const hex = (n) => n.toString(16).padStart(2, '0');
  return norm.map((o, i) => {
    let path = '';
    for (let h = 0, at = i; h < height; h++, at >>= 1) path += levels[h][at ^ 1].slice(2);
    return { order: o, signature: `0x${BULK_MAGIC}${hex(height)}${hex(i)}${path}${signature.slice(2)}` };
  });
}
