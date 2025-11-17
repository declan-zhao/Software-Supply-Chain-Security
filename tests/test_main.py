"""Unit tests for main.py module."""

import pytest
import json
import base64
import tempfile
import os
from unittest.mock import Mock, patch, mock_open, MagicMock
import requests

from src.main import (
    _validate_log_index,
    get_log_entry,
    get_verification_proof,
    inclusion,
    get_latest_checkpoint,
    get_consistency_proof_data,
    consistency,
)


class TestValidateLogIndex:
    """Test cases for _validate_log_index function."""

    def test_validate_log_index_valid(self):
        """Test _validate_log_index with valid index."""
        _validate_log_index(0)  # Should not raise
        _validate_log_index(1)  # Should not raise
        _validate_log_index(100)  # Should not raise

    def test_validate_log_index_negative(self):
        """Test _validate_log_index with negative index."""
        with pytest.raises(ValueError, match="log_index must be a non-negative integer"):
            _validate_log_index(-1)

    def test_validate_log_index_not_int(self):
        """Test _validate_log_index with non-integer."""
        with pytest.raises(ValueError, match="log_index must be a non-negative integer"):
            _validate_log_index("not an int")


class TestGetLogEntry:
    """Test cases for get_log_entry function."""

    @patch('src.main.requests.get')
    def test_get_log_entry_success(self, mock_get):
        """Test get_log_entry with successful API response."""
        mock_response = Mock()
        mock_response.json.return_value = {
            "abc123": {
                "body": "test",
                "integratedTime": 123456,
                "logID": "test",
                "logIndex": 0,
                "verification": {
                    "inclusionProof": {},
                    "signedEntryTimestamp": "test"
                }
            }
        }
        mock_response.raise_for_status = Mock()
        mock_get.return_value = mock_response

        result = get_log_entry(0)

        assert isinstance(result, dict)
        assert "abc123" in result
        mock_get.assert_called_once()

    @patch('src.main.requests.get')
    def test_get_log_entry_invalid_index(self, mock_get):
        """Test get_log_entry with invalid index."""
        with pytest.raises(ValueError):
            get_log_entry(-1)

        mock_get.assert_not_called()

    @patch('src.main.requests.get')
    def test_get_log_entry_invalid_response(self, mock_get):
        """Test get_log_entry with invalid response format."""
        mock_response = Mock()
        mock_response.json.return_value = []  # Not a dict
        mock_response.raise_for_status = Mock()
        mock_get.return_value = mock_response

        with pytest.raises(ValueError, match="Unexpected response format"):
            get_log_entry(0)

    @patch('src.main.requests.get')
    def test_get_log_entry_empty_response(self, mock_get):
        """Test get_log_entry with empty response."""
        mock_response = Mock()
        mock_response.json.return_value = {}  # Empty dict
        mock_response.raise_for_status = Mock()
        mock_get.return_value = mock_response

        with pytest.raises(ValueError, match="Unexpected response format"):
            get_log_entry(0)

    @patch('src.main.requests.get')
    def test_get_log_entry_api_error(self, mock_get):
        """Test get_log_entry with API error."""
        mock_response = Mock()
        mock_response.raise_for_status.side_effect = requests.HTTPError("API Error")
        mock_get.return_value = mock_response

        with pytest.raises(requests.HTTPError):
            get_log_entry(0)


class TestGetVerificationProof:
    """Test cases for get_verification_proof function."""

    def test_get_verification_proof_valid(self):
        """Test get_verification_proof with valid log entry."""
        log_entry = {
            "abc123": {
                "verification": {
                    "inclusionProof": {
                        "checkpoint": "test",
                        "hashes": ["hash1", "hash2"],
                        "logIndex": 0,
                        "rootHash": "root",
                        "treeSize": 10
                    }
                }
            }
        }

        result = get_verification_proof(log_entry)

        assert result == log_entry["abc123"]["verification"]["inclusionProof"]
        assert "checkpoint" in result
        assert "hashes" in result
        assert "logIndex" in result

    def test_get_verification_proof_empty_entry(self):
        """Test get_verification_proof with empty log entry."""
        log_entry = {}

        with pytest.raises(StopIteration):
            get_verification_proof(log_entry)


class TestInclusion:
    """Test cases for inclusion function."""

    def test_inclusion_invalid_log_index(self):
        """Test inclusion with invalid log index."""
        with pytest.raises(ValueError):
            inclusion(-1, "artifact.md")

    def test_inclusion_file_not_found(self):
        """Test inclusion with non-existent file."""
        with pytest.raises(FileNotFoundError, match="Artifact filepath invalid"):
            inclusion(0, "nonexistent_file.md")

    @patch('src.main.get_log_entry')
    @patch('src.main.extract_public_key')
    @patch('src.main.verify_artifact_signature')
    @patch('src.main.get_verification_proof')
    @patch('src.main.verify_inclusion')
    @patch('src.main.compute_leaf_hash')
    @patch('src.main.os.path.exists')
    @patch('src.main.os.path.isfile')
    @patch('src.main.base64.b64decode')
    @patch('src.main.json.loads')
    def test_inclusion_success(
        self,
        mock_json_loads,
        mock_b64decode,
        mock_isfile,
        mock_exists,
        mock_compute_leaf_hash,
        mock_verify_inclusion,
        mock_get_verification_proof,
        mock_verify_signature,
        mock_extract_key,
        mock_get_log_entry
    ):
        """Test inclusion with valid inputs."""
        # Setup mocks
        mock_exists.return_value = True
        mock_isfile.return_value = True

        # Create a valid mock body structure
        body_data = {
            "spec": {
                "signature": {
                    "publicKey": {"content": "dGVzdA=="},
                    "content": "c2ln"
                }
            }
        }
        body_json = json.dumps(body_data)
        body_base64 = base64.b64encode(body_json.encode()).decode()

        mock_log_entry = {
            "abc123": {
                "body": body_base64,
                "verification": {
                    "inclusionProof": {
                        "logIndex": 0,
                        "treeSize": 10,
                        "hashes": ["hash1"],
                        "rootHash": "root"
                    }
                }
            }
        }
        mock_get_log_entry.return_value = mock_log_entry
        mock_get_verification_proof.return_value = mock_log_entry["abc123"]["verification"]["inclusionProof"]
        mock_compute_leaf_hash.return_value = "leaf_hash"
        mock_extract_key.return_value = b"public_key"

        # Mock base64 decoding - decode body to JSON bytes, then decode cert/sig
        def b64decode_side_effect(data, **kwargs):
            if isinstance(data, str):
                if data == body_base64:
                    return body_json.encode()
                elif data == "dGVzdA==":
                    return b"decoded_cert"
                elif data == "c2ln":
                    return b"decoded_sig"
            return base64.b64decode(data, **kwargs)

        mock_b64decode.side_effect = b64decode_side_effect
        mock_json_loads.return_value = body_data

        # Create temporary file
        with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
            f.write("test artifact content")
            temp_file = f.name

        try:
            inclusion(0, temp_file)

            # Verify functions were called
            mock_get_log_entry.assert_called_once()
            mock_verify_signature.assert_called_once()
            mock_verify_inclusion.assert_called_once()
            mock_compute_leaf_hash.assert_called_once()
        finally:
            os.unlink(temp_file)


class TestGetLatestCheckpoint:
    """Test cases for get_latest_checkpoint function."""

    @patch('src.main.requests.get')
    def test_get_latest_checkpoint_success(self, mock_get):
        """Test get_latest_checkpoint with successful API response."""
        mock_response = Mock()
        mock_response.json.return_value = {
            "treeID": "123",
            "treeSize": 100,
            "rootHash": "hash",
            "signedTreeHead": "sth",
            "inactiveShards": []
        }
        mock_response.raise_for_status = Mock()
        mock_get.return_value = mock_response

        result = get_latest_checkpoint()

        assert isinstance(result, dict)
        assert "treeID" in result
        assert "treeSize" in result
        mock_get.assert_called_once()

    @patch('src.main.requests.get')
    def test_get_latest_checkpoint_invalid_response(self, mock_get):
        """Test get_latest_checkpoint with invalid response."""
        mock_response = Mock()
        mock_response.json.return_value = []  # Not a dict
        mock_response.raise_for_status = Mock()
        mock_get.return_value = mock_response

        with pytest.raises(ValueError, match="Unexpected response format"):
            get_latest_checkpoint()

    @patch('src.main.requests.get')
    def test_get_latest_checkpoint_api_error(self, mock_get):
        """Test get_latest_checkpoint with API error."""
        mock_response = Mock()
        mock_response.raise_for_status.side_effect = requests.HTTPError("API Error")
        mock_get.return_value = mock_response

        with pytest.raises(requests.HTTPError):
            get_latest_checkpoint()


class TestGetConsistencyProofData:
    """Test cases for get_consistency_proof_data function."""

    @patch('src.main.requests.get')
    def test_get_consistency_proof_data_success(self, mock_get):
        """Test get_consistency_proof_data with successful API response."""
        mock_response = Mock()
        mock_response.json.return_value = {
            "hashes": ["hash1", "hash2"]
        }
        mock_response.raise_for_status = Mock()
        mock_get.return_value = mock_response

        result = get_consistency_proof_data(10, 20, "tree_id")

        assert isinstance(result, dict)
        assert "hashes" in result
        mock_get.assert_called_once()

    def test_get_consistency_proof_data_invalid_first_size(self):
        """Test get_consistency_proof_data with invalid first_size."""
        with pytest.raises(ValueError, match="first_size must be a positive integer"):
            get_consistency_proof_data(0, 10, "tree_id")

        with pytest.raises(ValueError, match="first_size must be a positive integer"):
            get_consistency_proof_data(-1, 10, "tree_id")

    def test_get_consistency_proof_data_invalid_last_size(self):
        """Test get_consistency_proof_data with invalid last_size."""
        with pytest.raises(ValueError, match="last_size must be a positive integer"):
            get_consistency_proof_data(10, 0, "tree_id")

        with pytest.raises(ValueError, match="last_size must be a positive integer"):
            get_consistency_proof_data(10, -1, "tree_id")

    def test_get_consistency_proof_data_invalid_tree_id(self):
        """Test get_consistency_proof_data with invalid tree_id."""
        with pytest.raises(ValueError, match="tree_id must be a non-empty string"):
            get_consistency_proof_data(10, 20, "")

        with pytest.raises(ValueError, match="tree_id must be a non-empty string"):
            get_consistency_proof_data(10, 20, None)

    @patch('src.main.requests.get')
    def test_get_consistency_proof_data_invalid_response(self, mock_get):
        """Test get_consistency_proof_data with invalid response."""
        mock_response = Mock()
        mock_response.json.return_value = []  # Not a dict
        mock_response.raise_for_status = Mock()
        mock_get.return_value = mock_response

        with pytest.raises(ValueError, match="Unexpected response format"):
            get_consistency_proof_data(10, 20, "tree_id")


class TestConsistency:
    """Test cases for consistency function."""

    @patch('src.main.get_latest_checkpoint')
    @patch('src.main.get_consistency_proof_data')
    @patch('src.main.verify_consistency')
    def test_consistency_success(
        self,
        mock_verify_consistency,
        mock_get_consistency_proof,
        mock_get_latest_checkpoint
    ):
        """Test consistency with valid inputs."""
        prev_checkpoint = {
            "treeID": "123",
            "treeSize": 10,
            "rootHash": "prev_root"
        }

        mock_get_latest_checkpoint.return_value = {
            "treeSize": 20,
            "rootHash": "latest_root"
        }

        mock_get_consistency_proof.return_value = {
            "hashes": ["hash1", "hash2"]
        }

        consistency(prev_checkpoint)

        mock_get_latest_checkpoint.assert_called_once()
        mock_get_consistency_proof.assert_called_once_with(10, 20, "123", False)
        mock_verify_consistency.assert_called_once()

    @patch('src.main.get_latest_checkpoint')
    @patch('src.main.get_consistency_proof_data')
    @patch('src.main.verify_consistency')
    def test_consistency_with_debug(
        self,
        mock_verify_consistency,
        mock_get_consistency_proof,
        mock_get_latest_checkpoint
    ):
        """Test consistency with debug mode enabled."""
        prev_checkpoint = {
            "treeID": "123",
            "treeSize": 10,
            "rootHash": "prev_root"
        }

        mock_get_latest_checkpoint.return_value = {
            "treeSize": 20,
            "rootHash": "latest_root"
        }

        mock_get_consistency_proof.return_value = {
            "hashes": ["hash1", "hash2"]
        }

        consistency(prev_checkpoint, debug=True)

        mock_get_consistency_proof.assert_called_once_with(10, 20, "123", True)

    @patch('src.main.get_latest_checkpoint')
    def test_consistency_missing_tree_id(self, mock_get_latest_checkpoint):
        """Test consistency with missing treeID in checkpoint."""
        prev_checkpoint = {
            "treeSize": 10,
            "rootHash": "prev_root"
        }

        mock_get_latest_checkpoint.return_value = {
            "treeSize": 20,
            "rootHash": "latest_root"
        }

        # Should work but treeID will be None
        # This might cause issues in get_consistency_proof_data
        with patch('src.main.get_consistency_proof_data') as mock_get_proof:
            mock_get_proof.side_effect = ValueError("tree_id must be a non-empty string")
            with pytest.raises(ValueError):
                consistency(prev_checkpoint)

