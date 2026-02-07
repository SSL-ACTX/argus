def test_import_and_scan_json():
    import argus_ffi

    opts = argus_ffi.ScanOptions(
        targets=["."],
        keywords=["token"],
        entropy=False,
        deep_scan=False,
        flow_scan=False,
        request_trace=False,
        mode="scan",
    )

    out = argus_ffi.scan_json(opts)
    assert isinstance(out, str)
