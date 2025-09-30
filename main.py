import argparse
import base64
import json
import os
import requests
from util import extract_public_key, verify_artifact_signature
from merkle_proof import (
    DefaultHasher,
    verify_consistency,
    verify_inclusion,
    compute_leaf_hash,
)

REKOR_URL = "https://rekor.sigstore.dev/api/v1"


def get_log_entry(log_index, debug=False):
    if not isinstance(log_index, int) or log_index < 0:
        raise ValueError("log_index must be a non-negative integer.")

    url = f"{REKOR_URL}/log/entries"
    resp = requests.get(url, params={"logIndex": log_index})
    resp.raise_for_status()
    data = resp.json()

    if not isinstance(data, dict) or not data:
        raise ValueError("Unexpected response format for log entry.")

    if debug:
        with open("log_entry.json", "w") as f:
            json.dump(data, f, indent=4)

    return data


def get_verification_proof(log_index, debug=False):
    if not isinstance(log_index, int) or log_index < 0:
        raise ValueError("log_index must be a non-negative integer.")

    log_entry = get_log_entry(log_index, debug)
    key = next(iter(log_entry))
    value = log_entry[key]

    return value["verification"]["inclusionProof"]


def inclusion(log_index, artifact_filepath, debug=False):
    if not isinstance(log_index, int) or log_index < 0:
        raise ValueError("log_index must be a non-negative integer.")

    if not os.path.exists(artifact_filepath) or not os.path.isfile(artifact_filepath):
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
    verification_proof = get_verification_proof(log_index, debug)
    index = verification_proof["logIndex"]
    tree_size = verification_proof["treeSize"]
    leaf_hash = compute_leaf_hash(body)
    hashes = verification_proof["hashes"]
    root_hash = verification_proof["rootHash"]
    verify_inclusion(DefaultHasher, index, tree_size, leaf_hash, hashes, root_hash)
    print("Offline root hash calculation for inclusion verified.")


def get_latest_checkpoint(debug=False):
    url = f"{REKOR_URL}/log"
    resp = requests.get(url)
    resp.raise_for_status()
    data = resp.json()

    if not isinstance(data, dict) or not data:
        raise ValueError("Unexpected response format for checkpoint.")

    if debug:
        with open("checkpoint.json", "w") as f:
            json.dump(data, f, indent=4)

    return data


def get_consistency_proof_data(first_size, last_size, tree_id, debug=False):
    if not isinstance(first_size, int) or first_size < 1:
        raise ValueError("first_size must be a positive integer.")
    if not isinstance(last_size, int) or last_size < 1:
        raise ValueError("last_size must be a positive integer.")
    if not isinstance(tree_id, str) or not tree_id:
        raise ValueError("tree_id must be a non-empty string.")

    url = f"{REKOR_URL}/log/proof"
    resp = requests.get(
        url, params={"firstSize": first_size, "lastSize": last_size, "treeID": tree_id}
    )
    resp.raise_for_status()
    data = resp.json()

    if not isinstance(data, dict) or not data:
        raise ValueError("Unexpected response format for consistency proof.")

    if debug:
        with open("consistency_proof.json", "w") as f:
            json.dump(data, f, indent=4)

    return data


def consistency(prev_checkpoint, debug=False):
    prev_checkpoint_tree_id = prev_checkpoint.get("treeID")
    prev_checkpoint_tree_size = prev_checkpoint.get("treeSize")
    prev_checkpoint_root_hash = prev_checkpoint.get("rootHash")

    if (
        not prev_checkpoint
        or not prev_checkpoint_tree_id
        or not prev_checkpoint_tree_size
        or not prev_checkpoint_root_hash
    ):
        raise ValueError("Previous checkpoint is empty or missing required fields.")

    latest_checkpoint = get_latest_checkpoint(debug)
    if not latest_checkpoint:
        raise ValueError("Latest checkpoint is empty.")

    latest_checkpoint_tree_size = latest_checkpoint.get("treeSize")
    latest_checkpoint_root_hash = latest_checkpoint.get("rootHash")

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


def main():
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
        "--tree-size", help="Tree size for consistency proof", required=False, type=int
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
