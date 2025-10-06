"""
Rekor Transparency Log verifier.

CLI supports:
- Fetch log entry by index
- Verify artifact signature and Merkle inclusion
- Fetch latest checkpoint
- Verify Merkle consistency from prior checkpoint

Uses local merkle_proof (hash & proof verification)
and util (key extraction, signature check).
Add --debug to persist JSON responses for inspection.
"""

import argparse
import base64
import json
import os
from typing import Any, Dict

import requests
from util import extract_public_key, verify_artifact_signature
from merkle_proof import (
    DefaultHasher,
    verify_consistency,
    verify_inclusion,
    compute_leaf_hash,
)

REKOR_URL = "https://rekor.sigstore.dev/api/v1"

# Simple JSON object alias for clarity
JSONDict = Dict[str, Any]


def _validate_log_index(log_index: int) -> None:
    """Validate the log index.

    Args:
        log_index (int): The log index to validate.

    Raises:
        ValueError: If log_index is not a non-negative integer.
    """
    if not isinstance(log_index, int) or log_index < 0:
        raise ValueError("log_index must be a non-negative integer.")


def get_log_entry(log_index: int, debug: bool = False) -> JSONDict:
    """Retrieve a log entry from the Rekor API.

    Args:
        log_index (int): The log index to retrieve.
        debug (bool, optional): Whether to enable
            debug mode. Defaults to False.

    Raises:
        ValueError: If data is not a dict.

    Returns:
        data (dict): The log entry.
    """
    _validate_log_index(log_index)

    url = f"{REKOR_URL}/log/entries"
    resp = requests.get(url, params={"logIndex": log_index}, timeout=10)
    resp.raise_for_status()
    data = resp.json()

    if not isinstance(data, dict) or not data:
        raise ValueError("Unexpected response format for log entry.")

    if debug:
        with open("log_entry.json", "w", encoding="utf-8") as f:
            json.dump(data, f, indent=4)

    return data


def get_verification_proof(log_entry: JSONDict) -> JSONDict:
    """Get the verification proof from a log entry.

    Args:
        log_entry (dict): The log entry to extract the proof from.

    Returns:
        (dict) The verification proof.
    """
    key = next(iter(log_entry))
    value = log_entry[key]

    return value["verification"]["inclusionProof"]


def inclusion(
    log_index: int,
    artifact_filepath: str,
    debug: bool = False,
) -> None:
    """Verify the inclusion of an artifact in the transparency log.

    Args:
        log_index (int): The log index of the artifact.
        artifact_filepath (str): The file path to the artifact.
        debug (bool, optional): Whether to enable
            debug mode. Defaults to False.

    Raises:
        FileNotFoundError: If the artifact file is not found.
    """
    _validate_log_index(log_index)

    if not os.path.exists(artifact_filepath) or not os.path.isfile(
        artifact_filepath
    ):
        raise FileNotFoundError("Artifact filepath invalid.")

    log_entry = get_log_entry(log_index, debug)
    key = next(iter(log_entry))
    value = log_entry[key]

    body = value["body"]
    decoded_body_str = base64.b64decode(body).decode("utf-8")
    decoded_body = json.loads(decoded_body_str)

    # signature verification
    certificate = decoded_body["spec"]["signature"]["publicKey"]["content"]
    decoded_certificate = base64.b64decode(certificate)
    public_key = extract_public_key(decoded_certificate)

    signature = decoded_body["spec"]["signature"]["content"]
    decoded_signature = base64.b64decode(signature)

    verify_artifact_signature(decoded_signature, public_key, artifact_filepath)

    # inclusion verification
    verification_proof = get_verification_proof(log_entry)
    verify_inclusion(
        DefaultHasher,
        verification_proof["logIndex"],
        verification_proof["treeSize"],
        compute_leaf_hash(body),
        verification_proof["hashes"],
        verification_proof["rootHash"],
    )
    print("Offline root hash calculation for inclusion verified.")


def get_latest_checkpoint(debug: bool = False) -> JSONDict:
    """Get the latest checkpoint from the Rekor API.

    Args:
        debug (bool, optional): Whether to enable
            debug mode. Defaults to False.

    Raises:
        ValueError: If the response format is unexpected.

    Returns:
        data (dict): The latest checkpoint data.
    """
    url = f"{REKOR_URL}/log"
    resp = requests.get(url, timeout=10)
    resp.raise_for_status()
    data = resp.json()

    if not isinstance(data, dict) or not data:
        raise ValueError("Unexpected response format for checkpoint.")

    if debug:
        with open("checkpoint.json", "w", encoding="utf-8") as f:
            json.dump(data, f, indent=4)

    return data


def get_consistency_proof_data(
    first_size: int,
    last_size: int,
    tree_id: str,
    debug: bool = False,
) -> JSONDict:
    """Get the consistency proof data from the Rekor API.

    Args:
        first_size (int): The size of the first tree.
        last_size (int): The size of the last tree.
        tree_id (str): The tree ID.
        debug (bool, optional): Whether to enable
            debug mode. Defaults to False.

    Raises:
        ValueError: If the first_size is invalid.
        ValueError: If the last_size is invalid.
        ValueError: If the tree_id is invalid.

    Returns:
        data (dict): The consistency proof data.
    """
    if not isinstance(first_size, int) or first_size < 1:
        raise ValueError("first_size must be a positive integer.")
    if not isinstance(last_size, int) or last_size < 1:
        raise ValueError("last_size must be a positive integer.")
    if not isinstance(tree_id, str) or not tree_id:
        raise ValueError("tree_id must be a non-empty string.")

    url = f"{REKOR_URL}/log/proof"
    params: dict[str, int | str] = {
        "firstSize": first_size,
        "lastSize": last_size,
        "treeID": tree_id,
    }
    resp = requests.get(url, params=params, timeout=10)
    resp.raise_for_status()
    data = resp.json()

    if not isinstance(data, dict) or not data:
        raise ValueError("Unexpected response format for consistency proof.")

    if debug:
        with open("consistency_proof.json", "w", encoding="utf-8") as f:
            json.dump(data, f, indent=4)

    return data


def consistency(prev_checkpoint: JSONDict, debug: bool = False) -> None:
    """Verify the consistency of a previous
        checkpoint with the latest checkpoint.

    Args:
        prev_checkpoint (dict): The previous checkpoint data.
        debug (bool, optional): Whether to enable
            debug mode. Defaults to False.

    Raises:
        ValueError: If the previous checkpoint is invalid.
        ValueError: If the latest checkpoint is invalid.
    """
    # Extract and validate previous checkpoint fields
    prev_checkpoint_tree_id = prev_checkpoint.get("treeID")
    prev_checkpoint_tree_size = prev_checkpoint.get("treeSize")
    prev_checkpoint_root_hash = prev_checkpoint.get("rootHash")

    if (
        not isinstance(prev_checkpoint_tree_id, str)
        or not prev_checkpoint_tree_id
    ):
        raise ValueError("Previous checkpoint treeID missing or invalid.")
    if (
        not isinstance(prev_checkpoint_tree_size, int)
        or prev_checkpoint_tree_size < 1
    ):
        raise ValueError("Previous checkpoint treeSize missing or invalid.")
    if (
        not isinstance(prev_checkpoint_root_hash, str)
        or not prev_checkpoint_root_hash
    ):
        raise ValueError("Previous checkpoint rootHash missing or invalid.")

    latest_checkpoint = get_latest_checkpoint(debug)
    if not latest_checkpoint:
        raise ValueError("Latest checkpoint is empty.")

    latest_checkpoint_tree_size = latest_checkpoint.get("treeSize")
    latest_checkpoint_root_hash = latest_checkpoint.get("rootHash")

    if (
        not isinstance(latest_checkpoint_tree_size, int)
        or latest_checkpoint_tree_size < 1
    ):
        raise ValueError("Latest checkpoint treeSize missing or invalid.")
    if (
        not isinstance(latest_checkpoint_root_hash, str)
        or not latest_checkpoint_root_hash
    ):
        raise ValueError("Latest checkpoint rootHash missing or invalid.")

    consistency_proof = get_consistency_proof_data(
        prev_checkpoint_tree_size,
        latest_checkpoint_tree_size,
        prev_checkpoint_tree_id,
        debug,
    )
    proof = consistency_proof["hashes"]

    verify_consistency(
        DefaultHasher,
        prev_checkpoint_tree_size,
        latest_checkpoint_tree_size,
        proof,
        prev_checkpoint_root_hash,
        latest_checkpoint_root_hash,
    )
    print("Consistency verification successful.")


def main() -> None:
    """Main entry point for the Rekor Verifier."""
    debug = False
    parser = argparse.ArgumentParser(description="Rekor Verifier")
    parser.add_argument(
        "-d", "--debug", help="Debug mode", required=False, action="store_true"
    )  # Default false
    parser.add_argument(
        "-c",
        "--checkpoint",
        help="Obtain latest checkpoint\
                        from Rekor Server public instance",
        required=False,
        action="store_true",
    )
    parser.add_argument(
        "--inclusion",
        help="Verify inclusion of an\
                        entry in the Rekor Transparency Log using log index\
                        and artifact filename.\
                        Usage: --inclusion 126574567",
        required=False,
        type=int,
    )
    parser.add_argument(
        "--artifact",
        help="Artifact filepath for verifying\
                        signature",
        required=False,
    )
    parser.add_argument(
        "--consistency",
        help="Verify consistency of a given\
                        checkpoint with the latest checkpoint.",
        action="store_true",
    )
    parser.add_argument(
        "--tree-id", help="Tree ID for consistency proof", required=False
    )
    parser.add_argument(
        "--tree-size",
        help="Tree size for consistency proof",
        required=False,
        type=int,
    )
    parser.add_argument(
        "--root-hash", help="Root hash for consistency proof", required=False
    )
    args = parser.parse_args()
    if args.debug:
        debug = True
        print("enabled debug mode")
    if args.checkpoint:
        # get and print latest checkpoint from server
        # if debug is enabled, store it in a file checkpoint.json
        checkpoint = get_latest_checkpoint(debug)
        print(json.dumps(checkpoint, indent=4))
    if args.inclusion:
        inclusion(args.inclusion, args.artifact, debug)
    if args.consistency:
        if not args.tree_id:
            print("please specify tree id for prev checkpoint")
            return
        if not args.tree_size:
            print("please specify tree size for prev checkpoint")
            return
        if not args.root_hash:
            print("please specify root hash for prev checkpoint")
            return

        prev_checkpoint = {}
        prev_checkpoint["treeID"] = args.tree_id
        prev_checkpoint["treeSize"] = args.tree_size
        prev_checkpoint["rootHash"] = args.root_hash

        consistency(prev_checkpoint, debug)


if __name__ == "__main__":
    main()
