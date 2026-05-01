from __future__ import annotations
import pytest
import os

MASTER_SECRET = os.urandom(32)
USER_SUB_A = "user-a@corp.com"
USER_SUB_B = "user-b@corp.com"


@pytest.mark.unit
def test_encrypt_decrypt_roundtrip():
    from app.credential_broker.approaches.approach_a import encrypt, decrypt
    plaintext = "my-refresh-token-value"
    blob = encrypt(plaintext, USER_SUB_A, MASTER_SECRET)
    recovered = decrypt(blob, USER_SUB_A, MASTER_SECRET)
    assert recovered == plaintext


@pytest.mark.unit
def test_different_users_produce_different_blobs():
    from app.credential_broker.approaches.approach_a import encrypt
    blob_a = encrypt("token", USER_SUB_A, MASTER_SECRET)
    blob_b = encrypt("token", USER_SUB_B, MASTER_SECRET)
    assert blob_a != blob_b


@pytest.mark.unit
def test_wrong_user_cannot_decrypt():
    from app.credential_broker.approaches.approach_a import encrypt, decrypt
    from cryptography.exceptions import InvalidTag
    blob = encrypt("secret", USER_SUB_A, MASTER_SECRET)
    with pytest.raises(InvalidTag):
        decrypt(blob, USER_SUB_B, MASTER_SECRET)


@pytest.mark.unit
def test_nonce_is_random_each_time():
    from app.credential_broker.approaches.approach_a import encrypt
    blob1 = encrypt("token", USER_SUB_A, MASTER_SECRET)
    blob2 = encrypt("token", USER_SUB_A, MASTER_SECRET)
    assert blob1 != blob2
