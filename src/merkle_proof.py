"""
Merkle proof utilities implementing RFC 6962 (Certificate Transparency) style
Merkle Tree hashing, inclusion proof verification, and consistency proof
verification.

Main components:
- Hasher: Wrapper providing domain‑separated leaf and node hashing.
- verify_consistency: Validates a consistency proof between two tree sizes.
- verify_inclusion: Validates an inclusion proof for a leaf at a given index.
- root_from_inclusion_proof: Reconstructs a Merkle root from
    a leaf and its proof.
- compute_leaf_hash: Computes the RFC 6962 leaf hash from a base64-encoded
    log entry.

Helper chaining functions (chain_inner, chain_inner_right, chain_border_right)
compose partial proofs; decomp_incl_proof and inner_proof_size derive
structural parameters. RootMismatchError is raised when a calculated
root differs from an expected root.

All hashes use SHA-256 by default with explicit domain separation prefixes:
0x00 for leaves and 0x01 for internal nodes.
"""

import hashlib
import binascii
import base64

# domain separation prefixes according to the RFC
RFC6962_LEAF_HASH_PREFIX = 0
RFC6962_NODE_HASH_PREFIX = 1


class Hasher:
    """
    Hasher implements RFC 6962-style Merkle tree leaf and node hashing.
    This utility wraps a configurable cryptographic hash constructor
        (default: hashlib.sha256)
    and provides helpers to:
        - Produce an "empty" Merkle root (the digest of an untouched
            hash object).
        - Hash a leaf value with the RFC 6962 leaf prefix (0x00).
        - Hash two child node digests with the RFC 6962 node prefix (0x01).
        - Query the underlying digest size.
    RFC 6962 Prefix Conventions:
        - Leaf hash:  0x00 || leaf_bytes
        - Node hash:  0x01 || left_child_digest || right_child_digest
    Parameters
    ----------
    hash_func : Callable[[], 'hashlib._Hash'], optional
            A zero-argument callable returning a new hash object supporting
                .update() and .digest().
            Defaults to hashlib.sha256. Any hash function with the same
                interface may be supplied.
    Methods
    -------
    new() -> hashlib._Hash
            Return a fresh hash object from the configured hash constructor.
    empty_root() -> bytes
            Return the digest of an untouched hash object
                (the canonical empty tree root).
    hash_leaf(leaf: bytes) -> bytes
            Compute the RFC 6962 leaf hash for the given raw leaf bytes.
    hash_children(left: bytes, right: bytes) -> bytes
            Compute the RFC 6962 internal node hash from two child digests.
    size() -> int
            Return the digest size in bytes of the configured hash function.
    Usage Example
    -------------
            hasher = Hasher(hash_func=hashlib.sha256)
            leaf_digest = hasher.hash_leaf(b"example")
            combined = hasher.hash_children(leaf_digest, leaf_digest)
            empty = hasher.empty_root()
            digest_size = hasher.size()
    Notes
    -----
    - The caller is responsible for ensuring that 'left' and
        'right' in hash_children
        are already valid digest-sized byte strings.
    - This class does not perform tree management
        only primitive hashing operations.
    """

    def __init__(self, hash_func=hashlib.sha256):
        """Initialize the hasher.

        Parameters
        ----------
        hash_func : Callable[[], hashlib._Hash], optional
            Zero-argument callable returning a new hash object
            (default: hashlib.sha256).
        """
        self.hash_func = hash_func

    def new(self):
        """Return a fresh underlying hash object.

        Returns
        -------
        hashlib._Hash
            A new hash object instance.
        """
        return self.hash_func()

    def empty_root(self):
        """Return the canonical empty-tree root digest.

        Returns
        -------
        bytes
            Digest of an untouched hash object.
        """
        return self.new().digest()

    def hash_leaf(self, leaf):
        """Compute RFC 6962 leaf hash for raw leaf bytes.

        Parameters
        ----------
        leaf : bytes
            Raw (unhashed) leaf data.

        Returns
        -------
        bytes
            Leaf hash: 0x00 || leaf_bytes hashed with the underlying function.
        """
        h = self.new()
        h.update(bytes([RFC6962_LEAF_HASH_PREFIX]))
        h.update(leaf)
        return h.digest()

    def hash_children(self, left, right):
        """Compute internal node hash from two child digests.

        Parameters
        ----------
        left : bytes
            Left child digest (must be digest-sized).
        right : bytes
            Right child digest (must be digest-sized).

        Returns
        -------
        bytes
            Parent digest: hash(0x01 || left || right).
        """
        h = self.new()
        b = bytes([RFC6962_NODE_HASH_PREFIX]) + left + right
        h.update(b)
        return h.digest()

    def size(self):
        """Return digest size in bytes of the configured hash function.

        Returns
        -------
        int
            Digest size in bytes.
        """
        return self.new().digest_size


# DefaultHasher is a SHA256 based LogHasher
DefaultHasher = Hasher(hashlib.sha256)


def verify_consistency(
    hasher, size1, size2, proof, root1, root2
):  # pylint: disable=too-many-arguments, too-many-positional-arguments, too-many-locals # noqa: E501
    """Verify a Merkle tree consistency proof between two tree sizes.

    Validates that a tree of size ``size2`` is an append-only extension of a
    tree of size ``size1`` using an RFC 6962 style consistency proof.

    Parameters
    ----------
    hasher : Hasher
        Hasher instance implementing RFC 6962 leaf / node hashing.
    size1 : int
        Original (smaller) tree size.
    size2 : int
        New (larger or equal) tree size.
    proof : list[str]
        Sequence of hex-encoded node hashes constituting the consistency proof.
    root1 : str
        Hex-encoded root hash of the original tree of size ``size1``.
    root2 : str
        Hex-encoded root hash of the larger tree of size ``size2``.

    Raises
    ------
    ValueError
        If provided sizes are invalid, or the proof structure length is
        inconsistent with expectations.
    RootMismatchError
        If recomputed roots do not match the supplied roots.
    """
    # change format of args to be bytearray instead of hex strings
    root1 = bytes.fromhex(root1)
    root2 = bytes.fromhex(root2)
    bytearray_proof = []
    for elem in proof:
        bytearray_proof.append(bytes.fromhex(elem))

    if size2 < size1:
        raise ValueError(f"size2 ({size2}) < size1 ({size1})")
    if size1 == size2:
        if bytearray_proof:
            raise ValueError("size1=size2, but bytearray_proof is not empty")
        verify_match(root1, root2)
        return
    if size1 == 0:
        if bytearray_proof:
            raise ValueError(
                "expected empty bytearray_proof, "
                f"but got {len(bytearray_proof)} components"
            )
        return
    if not bytearray_proof:
        raise ValueError("empty bytearray_proof")

    inner, border = decomp_incl_proof(size1 - 1, size2)
    shift = (size1 & -size1).bit_length() - 1
    inner -= shift

    if size1 == 1 << shift:
        seed, start = root1, 0
    else:
        seed, start = bytearray_proof[0], 1

    if len(bytearray_proof) != start + inner + border:
        raise ValueError(
            "wrong bytearray_proof size "
            f"{len(bytearray_proof)}, "
            f"want {start + inner + border}"
        )

    bytearray_proof = bytearray_proof[start:]

    mask = (size1 - 1) >> shift
    hash1 = chain_inner_right(hasher, seed, bytearray_proof[:inner], mask)
    hash1 = chain_border_right(hasher, hash1, bytearray_proof[inner:])
    verify_match(hash1, root1)

    hash2 = chain_inner(hasher, seed, bytearray_proof[:inner], mask)
    hash2 = chain_border_right(hasher, hash2, bytearray_proof[inner:])
    verify_match(hash2, root2)


def verify_match(calculated, expected):
    """Raise ``RootMismatchError`` if two digests differ.

    Parameters
    ----------
    calculated : bytes
        Locally computed root digest.
    expected : bytes
        Expected / supplied root digest.
    """
    if calculated != expected:
        raise RootMismatchError(expected, calculated)


def decomp_incl_proof(index, size):
    """Decompose an inclusion proof into inner and border component counts.

    Splits the total proof path length for a leaf at ``index`` in a tree of
    ``size`` leaves into:
      * ``inner``: number of nodes on the fully balanced (inner) portion.
      * ``border``: number of right-border nodes determined by set bits
        beyond the inner portion.

    Returns
    -------
    tuple[int, int]
        (inner, border)
    """
    inner = inner_proof_size(index, size)
    border = bin(index >> inner).count("1")
    return inner, border


def inner_proof_size(index, size):
    """Return the number of inner (balanced) proof nodes for a leaf.

    Computed as the bit-length of ``index ^ (size - 1)`` per RFC 6962 logic.
    """
    return (index ^ (size - 1)).bit_length()


def chain_inner(hasher, seed, proof, index):
    """Fold the "inner" portion of an inclusion / consistency proof.

    Parameters
    ----------
    hasher : Hasher
        Hashing helper.
    seed : bytes
        Starting digest (leaf hash or prior node).
    proof : Sequence[bytes]
        Ordered sibling node digests for the inner portion.
    index : int
        Leaf index (or mask) used to determine left/right concatenation order.

    Returns
    -------
    bytes
        Resulting digest after folding all inner nodes.
    """
    for i, h in enumerate(proof):
        if (index >> i) & 1 == 0:
            seed = hasher.hash_children(seed, h)
        else:
            seed = hasher.hash_children(h, seed)
    return seed


def chain_inner_right(hasher, seed, proof, index):
    """Fold only the right-branching inner proof nodes.

    Used in consistency proof reconstruction (right-hand variant). Only
    processes nodes where the corresponding bit in ``index`` is 1.
    """
    for i, h in enumerate(proof):
        if (index >> i) & 1 == 1:
            seed = hasher.hash_children(h, seed)
    return seed


def chain_border_right(hasher, seed, proof):
    """Fold the border (right-hand) portion of a proof deterministically.

    Parameters
    ----------
    hasher : Hasher
        Hashing helper.
    seed : bytes
        Starting digest from prior inner folding.
    proof : Sequence[bytes]
        Remaining sibling hashes along the right border.

    Returns
    -------
    bytes
        Final digest after incorporating all border nodes.
    """
    for h in proof:
        seed = hasher.hash_children(h, seed)
    return seed


class RootMismatchError(Exception):
    """Exception raised when a reconstructed Merkle root mismatches expected.

    Attributes
    ----------
    expected_root : bytes (hexlified)
        The expected (supplied) root digest in hex representation.
    calculated_root : bytes (hexlified)
        The locally reconstructed root digest in hex representation.
    """

    def __init__(self, expected_root, calculated_root):
        self.expected_root = binascii.hexlify(bytearray(expected_root))
        self.calculated_root = binascii.hexlify(bytearray(calculated_root))

    def __str__(self):
        return (
            "calculated root:\n"
            f"{self.calculated_root}\n does not match "
            f"expected root:\n{self.expected_root}"
        )


def root_from_inclusion_proof(hasher, index, size, leaf_hash, proof):
    """Reconstruct the Merkle root from an inclusion proof.

    Parameters
    ----------
    hasher : Hasher
        Hasher instance.
    index : int
        Zero-based leaf index.
    size : int
        Total number of leaves in the tree.
    leaf_hash : bytes
        RFC 6962 leaf hash (already domain-separated) for the target leaf.
    proof : Sequence[bytes]
        Ordered sibling hashes for the inclusion path.

    Returns
    -------
    bytes
        Reconstructed Merkle root digest.

    Raises
    ------
    ValueError
        If ``index`` is outside the tree size, if ``leaf_hash`` size is wrong,
        or if proof length is inconsistent with tree structure.
    """
    if index >= size:
        raise ValueError(f"index is beyond size: {index} >= {size}")

    if len(leaf_hash) != hasher.size():
        raise ValueError(
            "leaf_hash has unexpected size "
            f"{len(leaf_hash)}, want {hasher.size()}"
        )

    inner, border = decomp_incl_proof(index, size)
    if len(proof) != inner + border:
        raise ValueError(
            f"wrong proof size {len(proof)}, want {inner + border}"
        )

    res = chain_inner(hasher, leaf_hash, proof[:inner], index)
    res = chain_border_right(hasher, res, proof[inner:])
    return res


def verify_inclusion(
    hasher, index, size, leaf_hash, proof, root, debug=False
):  # pylint: disable=too-many-arguments, too-many-positional-arguments
    """Verify an inclusion proof for a given leaf index and root.

    Parameters
    ----------
    hasher : Hasher
        Hashing helper.
    index : int
        Zero-based index of the leaf.
    size : int
        Total number of leaves in the tree.
    leaf_hash : str
        Hex-encoded RFC 6962 leaf hash.
    proof : list[str]
        Sequence of hex-encoded sibling hashes.
    root : str
        Expected hex-encoded Merkle root digest.
    debug : bool, optional
        If True, prints computed vs provided root for inspection.

    Raises
    ------
    RootMismatchError
        If reconstructed root does not match supplied root.
    ValueError
        If tree / proof structural constraints are violated.
    """
    bytearray_proof = []
    for elem in proof:
        bytearray_proof.append(bytes.fromhex(elem))

    bytearray_root = bytes.fromhex(root)
    bytearray_leaf = bytes.fromhex(leaf_hash)
    calc_root = root_from_inclusion_proof(
        hasher, index, size, bytearray_leaf, bytearray_proof
    )
    verify_match(calc_root, bytearray_root)
    if debug:
        print("Calculated root hash", calc_root.hex())
        print("Given root hash", bytearray_root.hex())


# requires entry["body"] output for a log entry
# returns the leaf hash according to the rfc 6962 spec
def compute_leaf_hash(body):
    """Compute the RFC 6962 leaf hash for a base64-encoded log entry body.

    The function performs base64 decoding, then applies the leaf domain
    separation prefix (0x00) prior to hashing with SHA-256.

    Parameters
    ----------
    body : str
        Base64-encoded string representing the raw log entry (JSON or binary).

    Returns
    -------
    str
        Hex-encoded SHA-256 digest of the prefixed leaf bytes.
    """
    entry_bytes = base64.b64decode(body)

    # create a new sha256 hash object
    h = hashlib.sha256()
    # write the leaf hash prefix
    h.update(bytes([RFC6962_LEAF_HASH_PREFIX]))

    # write the actual leaf data
    h.update(entry_bytes)

    # return the computed hash
    return h.hexdigest()
