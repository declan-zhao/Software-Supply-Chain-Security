"""Unit tests for merkle_proof.py module."""

import pytest
import hashlib
import base64
from merkle_proof import (
    Hasher,
    DefaultHasher,
    verify_consistency,
    verify_inclusion,
    compute_leaf_hash,
    root_from_inclusion_proof,
    verify_match,
    decomp_incl_proof,
    inner_proof_size,
    chain_inner,
    chain_inner_right,
    chain_border_right,
    RootMismatchError,
    RFC6962_LEAF_HASH_PREFIX,
    RFC6962_NODE_HASH_PREFIX,
)


class TestHasher:
    """Test cases for Hasher class."""

    def test_hasher_init_default(self):
        """Test Hasher initialization with default hash function."""
        hasher = Hasher()
        assert hasher.hash_func == hashlib.sha256

    def test_hasher_init_custom(self):
        """Test Hasher initialization with custom hash function."""
        hasher = Hasher(hash_func=hashlib.sha512)
        assert hasher.hash_func == hashlib.sha512

    def test_hasher_new(self):
        """Test Hasher.new() returns a fresh hash object."""
        hasher = Hasher()
        h1 = hasher.new()
        h2 = hasher.new()
        assert h1 is not h2

    def test_hasher_empty_root(self):
        """Test Hasher.empty_root() returns correct empty root."""
        hasher = Hasher()
        empty_root = hasher.empty_root()

        # Empty root should be the digest of an untouched hash object
        expected = hashlib.sha256().digest()
        assert empty_root == expected

    def test_hasher_hash_leaf(self):
        """Test Hasher.hash_leaf() produces correct leaf hash."""
        hasher = Hasher()
        leaf_data = b"test leaf data"

        leaf_hash = hasher.hash_leaf(leaf_data)

        # Manually compute expected hash
        expected = hashlib.sha256()
        expected.update(bytes([RFC6962_LEAF_HASH_PREFIX]))
        expected.update(leaf_data)
        expected_hash = expected.digest()

        assert leaf_hash == expected_hash
        assert len(leaf_hash) == 32  # SHA-256 produces 32-byte digests

    def test_hasher_hash_children(self):
        """Test Hasher.hash_children() produces correct node hash."""
        hasher = Hasher()
        left = hashlib.sha256(b"left").digest()
        right = hashlib.sha256(b"right").digest()

        node_hash = hasher.hash_children(left, right)

        # Manually compute expected hash
        expected = hashlib.sha256()
        expected.update(bytes([RFC6962_NODE_HASH_PREFIX]))
        expected.update(left)
        expected.update(right)
        expected_hash = expected.digest()

        assert node_hash == expected_hash
        assert len(node_hash) == 32

    def test_hasher_size(self):
        """Test Hasher.size() returns correct digest size."""
        hasher = Hasher()
        assert hasher.size() == 32  # SHA-256 digest size

        hasher_512 = Hasher(hash_func=hashlib.sha512)
        assert hasher_512.size() == 64  # SHA-512 digest size

    def test_hasher_hash_children_order_matters(self):
        """Test that hash_children is order-sensitive."""
        hasher = Hasher()
        left = hashlib.sha256(b"left").digest()
        right = hashlib.sha256(b"right").digest()

        hash1 = hasher.hash_children(left, right)
        hash2 = hasher.hash_children(right, left)

        assert hash1 != hash2


class TestDefaultHasher:
    """Test cases for DefaultHasher."""

    def test_default_hasher_is_hasher_instance(self):
        """Test that DefaultHasher is a Hasher instance."""
        assert isinstance(DefaultHasher, Hasher)

    def test_default_hasher_uses_sha256(self):
        """Test that DefaultHasher uses SHA-256."""
        assert DefaultHasher.hash_func == hashlib.sha256


class TestComputeLeafHash:
    """Test cases for compute_leaf_hash function."""

    def test_compute_leaf_hash_valid(self):
        """Test compute_leaf_hash with valid base64 input."""
        test_data = b"test data"
        base64_data = base64.b64encode(test_data).decode('utf-8')

        leaf_hash = compute_leaf_hash(base64_data)

        # Manually compute expected hash
        expected = hashlib.sha256()
        expected.update(bytes([RFC6962_LEAF_HASH_PREFIX]))
        expected.update(test_data)
        expected_hash = expected.hexdigest()

        assert leaf_hash == expected_hash
        assert isinstance(leaf_hash, str)
        assert len(leaf_hash) == 64  # Hex-encoded SHA-256

    def test_compute_leaf_hash_empty(self):
        """Test compute_leaf_hash with empty input."""
        base64_data = base64.b64encode(b"").decode('utf-8')
        leaf_hash = compute_leaf_hash(base64_data)

        expected = hashlib.sha256()
        expected.update(bytes([RFC6962_LEAF_HASH_PREFIX]))
        expected_hash = expected.hexdigest()

        assert leaf_hash == expected_hash

    def test_compute_leaf_hash_deterministic(self):
        """Test that compute_leaf_hash is deterministic."""
        test_data = b"test data"
        base64_data = base64.b64encode(test_data).decode('utf-8')

        hash1 = compute_leaf_hash(base64_data)
        hash2 = compute_leaf_hash(base64_data)

        assert hash1 == hash2


class TestInnerProofSize:
    """Test cases for inner_proof_size function."""

    def test_inner_proof_size_simple(self):
        """Test inner_proof_size with simple cases."""
        # For index 0, size 1: 0 ^ (1-1) = 0 ^ 0 = 0, bit_length = 0
        assert inner_proof_size(0, 1) == 0

        # For index 0, size 2: 0 ^ (2-1) = 0 ^ 1 = 1, bit_length = 1
        assert inner_proof_size(0, 2) == 1

        # For index 1, size 2: 1 ^ (2-1) = 1 ^ 1 = 0, bit_length = 0
        assert inner_proof_size(1, 2) == 0

    def test_inner_proof_size_larger(self):
        """Test inner_proof_size with larger values."""
        # Index 5 (101), size 8 (1000): 5 ^ 7 = 101 ^ 111 = 010, bit_length = 2
        result = inner_proof_size(5, 8)
        assert result >= 0
        assert isinstance(result, int)


class TestDecompInclProof:
    """Test cases for decomp_incl_proof function."""

    def test_decomp_incl_proof_simple(self):
        """Test decomp_incl_proof with simple cases."""
        inner, border = decomp_incl_proof(0, 1)
        assert inner == 0
        assert border == 0

        inner, border = decomp_incl_proof(0, 2)
        assert inner >= 0
        assert border >= 0
        assert isinstance(inner, int)
        assert isinstance(border, int)

    def test_decomp_incl_proof_returns_tuple(self):
        """Test that decomp_incl_proof returns a tuple."""
        result = decomp_incl_proof(5, 10)
        assert isinstance(result, tuple)
        assert len(result) == 2


class TestChainFunctions:
    """Test cases for chain_inner, chain_inner_right, and chain_border_right."""

    def test_chain_inner_empty_proof(self):
        """Test chain_inner with empty proof."""
        hasher = DefaultHasher
        seed = hasher.hash_leaf(b"test")
        proof = []
        index = 0

        result = chain_inner(hasher, seed, proof, index)
        assert result == seed

    def test_chain_inner_single_node(self):
        """Test chain_inner with single proof node."""
        hasher = DefaultHasher
        seed = hasher.hash_leaf(b"test")
        proof_node = hasher.hash_leaf(b"proof")
        proof = [proof_node]
        index = 0  # Left branch

        result = chain_inner(hasher, seed, proof, index)
        expected = hasher.hash_children(seed, proof_node)
        assert result == expected

    def test_chain_inner_right_empty(self):
        """Test chain_inner_right with empty proof."""
        hasher = DefaultHasher
        seed = hasher.hash_leaf(b"test")
        proof = []
        index = 0

        result = chain_inner_right(hasher, seed, proof, index)
        assert result == seed

    def test_chain_border_right_empty(self):
        """Test chain_border_right with empty proof."""
        hasher = DefaultHasher
        seed = hasher.hash_leaf(b"test")
        proof = []

        result = chain_border_right(hasher, seed, proof)
        assert result == seed

    def test_chain_border_right_single_node(self):
        """Test chain_border_right with single proof node."""
        hasher = DefaultHasher
        seed = hasher.hash_leaf(b"test")
        proof_node = hasher.hash_leaf(b"proof")
        proof = [proof_node]

        result = chain_border_right(hasher, seed, proof)
        expected = hasher.hash_children(proof_node, seed)
        assert result == expected


class TestVerifyMatch:
    """Test cases for verify_match function."""

    def test_verify_match_success(self):
        """Test verify_match with matching roots."""
        root = b"test root hash data"
        verify_match(root, root)  # Should not raise

    def test_verify_match_failure(self):
        """Test verify_match with mismatching roots."""
        root1 = b"test root hash data 1"
        root2 = b"test root hash data 2"

        with pytest.raises(RootMismatchError):
            verify_match(root1, root2)


class TestRootMismatchError:
    """Test cases for RootMismatchError exception."""

    def test_root_mismatch_error_creation(self):
        """Test RootMismatchError creation."""
        expected = b"expected"
        calculated = b"calculated"

        error = RootMismatchError(expected, calculated)
        assert error.expected_root is not None
        assert error.calculated_root is not None

    def test_root_mismatch_error_str(self):
        """Test RootMismatchError string representation."""
        expected = b"expected"
        calculated = b"calculated"

        error = RootMismatchError(expected, calculated)
        error_str = str(error)

        assert "calculated root" in error_str.lower()
        assert "expected root" in error_str.lower()


class TestRootFromInclusionProof:
    """Test cases for root_from_inclusion_proof function."""

    def test_root_from_inclusion_proof_single_leaf(self):
        """Test root_from_inclusion_proof with single leaf tree."""
        hasher = DefaultHasher
        index = 0
        size = 1
        leaf_hash = hasher.hash_leaf(b"test")
        proof = []

        root = root_from_inclusion_proof(hasher, index, size, leaf_hash, proof)

        # For a single leaf, root should equal the leaf hash
        assert root == leaf_hash

    def test_root_from_inclusion_proof_two_leaves(self):
        """Test root_from_inclusion_proof with two-leaf tree."""
        hasher = DefaultHasher
        index = 0
        size = 2
        leaf_hash = hasher.hash_leaf(b"left")
        sibling_hash = hasher.hash_leaf(b"right")
        proof = [sibling_hash]

        root = root_from_inclusion_proof(hasher, index, size, leaf_hash, proof)

        # Root should be hash of left and right children
        expected_root = hasher.hash_children(leaf_hash, sibling_hash)
        assert root == expected_root

    def test_root_from_inclusion_proof_index_out_of_bounds(self):
        """Test root_from_inclusion_proof with index >= size."""
        hasher = DefaultHasher
        index = 5
        size = 3
        leaf_hash = hasher.hash_leaf(b"test")
        proof = []

        with pytest.raises(ValueError, match="index is beyond size"):
            root_from_inclusion_proof(hasher, index, size, leaf_hash, proof)

    def test_root_from_inclusion_proof_wrong_leaf_hash_size(self):
        """Test root_from_inclusion_proof with wrong leaf hash size."""
        hasher = DefaultHasher
        index = 0
        size = 1
        leaf_hash = b"wrong size"  # Not 32 bytes
        proof = []

        with pytest.raises(ValueError, match="leaf_hash has unexpected size"):
            root_from_inclusion_proof(hasher, index, size, leaf_hash, proof)

    def test_root_from_inclusion_proof_wrong_proof_size(self):
        """Test root_from_inclusion_proof with wrong proof size."""
        hasher = DefaultHasher
        index = 0
        size = 2
        leaf_hash = hasher.hash_leaf(b"test")
        proof = []  # Should have 1 element for size=2

        with pytest.raises(ValueError, match="wrong proof size"):
            root_from_inclusion_proof(hasher, index, size, leaf_hash, proof)


class TestVerifyInclusion:
    """Test cases for verify_inclusion function."""

    def test_verify_inclusion_single_leaf(self):
        """Test verify_inclusion with single leaf tree."""
        hasher = DefaultHasher
        index = 0
        size = 1
        leaf_hash = hasher.hash_leaf(b"test").hex()
        proof = []
        root = hasher.hash_leaf(b"test").hex()

        # Should not raise
        verify_inclusion(hasher, index, size, leaf_hash, proof, root)

    def test_verify_inclusion_two_leaves(self):
        """Test verify_inclusion with two-leaf tree."""
        hasher = DefaultHasher
        index = 0
        size = 2
        left_hash = hasher.hash_leaf(b"left")
        right_hash = hasher.hash_leaf(b"right")
        root = hasher.hash_children(left_hash, right_hash)

        leaf_hash = left_hash.hex()
        proof = [right_hash.hex()]
        root_hex = root.hex()

        # Should not raise
        verify_inclusion(hasher, index, size, leaf_hash, proof, root_hex)

    def test_verify_inclusion_wrong_root(self):
        """Test verify_inclusion with wrong root hash."""
        hasher = DefaultHasher
        index = 0
        size = 1
        leaf_hash = hasher.hash_leaf(b"test").hex()
        proof = []
        wrong_root = hasher.hash_leaf(b"wrong").hex()

        with pytest.raises(RootMismatchError):
            verify_inclusion(hasher, index, size, leaf_hash, proof, wrong_root)

    def test_verify_inclusion_debug_mode(self, capsys):
        """Test verify_inclusion with debug mode enabled."""
        hasher = DefaultHasher
        index = 0
        size = 1
        leaf_hash = hasher.hash_leaf(b"test").hex()
        proof = []
        root = hasher.hash_leaf(b"test").hex()

        verify_inclusion(hasher, index, size, leaf_hash, proof, root, debug=True)

        captured = capsys.readouterr()
        assert "Calculated root hash" in captured.out
        assert "Given root hash" in captured.out


class TestVerifyConsistency:
    """Test cases for verify_consistency function."""

    def test_verify_consistency_same_size(self):
        """Test verify_consistency when size1 == size2."""
        hasher = DefaultHasher
        size1 = 5
        size2 = 5
        proof = []
        root = hasher.hash_leaf(b"test").hex()

        # Should not raise
        verify_consistency(hasher, size1, size2, proof, root, root)

    def test_verify_consistency_same_size_non_empty_proof(self):
        """Test verify_consistency when size1 == size2 but proof is non-empty."""
        hasher = DefaultHasher
        size1 = 5
        size2 = 5
        proof = ["abcdef"]
        root = hasher.hash_leaf(b"test").hex()

        with pytest.raises(ValueError, match="size1=size2, but bytearray_proof is not empty"):
            verify_consistency(hasher, size1, size2, proof, root, root)

    def test_verify_consistency_size2_less_than_size1(self):
        """Test verify_consistency when size2 < size1."""
        hasher = DefaultHasher
        size1 = 10
        size2 = 5
        proof = []
        root = hasher.hash_leaf(b"test").hex()

        with pytest.raises(ValueError, match="size2.*< size1"):
            verify_consistency(hasher, size1, size2, proof, root, root)

    def test_verify_consistency_size1_zero(self):
        """Test verify_consistency when size1 == 0."""
        hasher = DefaultHasher
        size1 = 0
        size2 = 5
        proof = []
        root1 = hasher.hash_leaf(b"test").hex()
        root2 = hasher.hash_leaf(b"test2").hex()

        # Should not raise when proof is empty
        verify_consistency(hasher, size1, size2, proof, root1, root2)

    def test_verify_consistency_size1_zero_non_empty_proof(self):
        """Test verify_consistency when size1 == 0 but proof is non-empty."""
        hasher = DefaultHasher
        size1 = 0
        size2 = 5
        proof = ["abcdef"]
        root1 = hasher.hash_leaf(b"test").hex()
        root2 = hasher.hash_leaf(b"test2").hex()

        with pytest.raises(ValueError, match="expected empty bytearray_proof"):
            verify_consistency(hasher, size1, size2, proof, root1, root2)

    def test_verify_consistency_empty_proof(self):
        """Test verify_consistency with empty proof when it shouldn't be."""
        hasher = DefaultHasher
        size1 = 5
        size2 = 10
        proof = []
        root1 = hasher.hash_leaf(b"test").hex()
        root2 = hasher.hash_leaf(b"test2").hex()

        with pytest.raises(ValueError, match="empty bytearray_proof"):
            verify_consistency(hasher, size1, size2, proof, root1, root2)

    def test_verify_consistency_invalid_proof_size(self):
        """Test verify_consistency with invalid proof size."""
        hasher = DefaultHasher
        size1 = 4
        size2 = 8
        # Create invalid proof (wrong size)
        proof = ["abcdef"] * 10  # Too many or too few
        root1 = hasher.hash_leaf(b"test").hex()
        root2 = hasher.hash_leaf(b"test2").hex()

        # This may raise ValueError or RootMismatchError depending on the proof
        with pytest.raises((ValueError, RootMismatchError)):
            verify_consistency(hasher, size1, size2, proof, root1, root2)

