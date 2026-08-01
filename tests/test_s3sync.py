import os

from botocore.exceptions import ClientError

from ichnos.s3sync import download_file
from ichnos.s3sync import upload_file


class FakeS3Client:
    def __init__(self, objects=None):
        self.objects = objects or {}
        self.uploaded = []

    def upload_file(self, local_path, bucket, key):
        with open(local_path, "rb") as f:
            self.uploaded.append((bucket, key, f.read()))

    def download_file(self, bucket, key, local_path):
        content = self.objects.get((bucket, key))
        if content is None:
            raise ClientError(
                {"Error": {"Code": "404", "Message": "Not Found"}}, "GetObject"
            )
        with open(local_path, "wb") as f:
            f.write(content)


def test_upload_file_sends_bytes_to_the_right_bucket_and_key(tmp_path):
    local_path = tmp_path / "blocklist.conf"
    local_path.write_text("10.0.0.0/8\n")
    client = FakeS3Client()

    upload_file("my-bucket", "jurisdiction/blocklist.conf", str(local_path), client=client)

    assert client.uploaded == [("my-bucket", "jurisdiction/blocklist.conf", b"10.0.0.0/8\n")]


def test_download_file_returns_true_and_writes_content_when_object_exists(tmp_path):
    client = FakeS3Client(objects={("my-bucket", "k"): b"5.6.7.0/24\n"})
    dest = str(tmp_path / "nested" / "blocklist.conf")

    found = download_file("my-bucket", "k", dest, client=client)

    assert found is True
    with open(dest) as f:
        assert f.read() == "5.6.7.0/24\n"


def test_download_file_returns_false_when_object_missing(tmp_path):
    client = FakeS3Client()
    dest = str(tmp_path / "blocklist.conf")

    found = download_file("my-bucket", "does-not-exist", dest, client=client)

    assert found is False
    assert not os.path.exists(dest)


def test_download_file_reraises_non_404_errors(tmp_path):
    class DenyingClient(FakeS3Client):
        def download_file(self, bucket, key, local_path):
            raise ClientError(
                {"Error": {"Code": "AccessDenied", "Message": "nope"}}, "GetObject"
            )

    try:
        download_file("my-bucket", "k", str(tmp_path / "x.conf"), client=DenyingClient())
        raise AssertionError("expected ClientError to propagate")
    except ClientError as exc:
        assert exc.response["Error"]["Code"] == "AccessDenied"
