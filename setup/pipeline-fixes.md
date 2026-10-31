# Data-pipeline fixes found during the evals

Detection work keeps surfacing data-quality issues upstream. This is where they're recorded.

## Duplicate `IpAddress` extraction in `win_dc` (XmlWinEventLog)

**Symptom.** In `win_dc`, `IpAddress` came back as a multivalue field with two identical values
(e.g. `["::ffff:10.0.30.100","::ffff:10.0.30.100"]`). This silently broke searches: `replace()`
and `by src_ip` on a multivalue field return null / drop the row. It bit the brute-force detection
(Eval 01/02) and again the Kerberoasting detection (Eval 06) — the AI's first draft missed the test
event both times for this reason.

**Diagnosis.** The raw XML contains `IpAddress` once, but Splunk extracted it twice:

```
raw_ipaddr_count = 1
extracted_count  = 2
```

`btool` pinned the cause: a **redundant custom extraction** layered on top of the official add-on.

```
search/local/props.conf              EXTRACT-ipaddress = Name='IpAddress'>(?<IpAddress>[^<]+)
Splunk_TA_windows/default/props.conf REPORT-0xml_kv_extract = ... eventdata_xml_data ...   # already extracts IpAddress
```

The Splunk Add-on for Windows already parses `<Data Name='IpAddress'>` via its generic
`eventdata_xml_data` report. The hand-added `EXTRACT-ipaddress` in `search/local` was a second
rule producing the same field → multivalue.

**Fix.** Remove only the redundant `EXTRACT-ipaddress` from the `[XmlWinEventLog]` stanza in
`search/local/props.conf` (leave `EVAL-src = IpAddress`), then refresh (`/debug/refresh`, no restart):

```ini
[XmlWinEventLog]
EVAL-src = IpAddress
```

**Result (verified via MCP):** `IpAddress` is now single-valued, **and** the CIM `src` field — which
`EVAL-src = IpAddress` had been failing to populate because EVAL over a multivalue field fails — now
populates correctly. Two bugs fixed by removing one line.

**Takeaway.** When a stock TA already extracts a field, don't add a second extraction for it in a
local app; you get a silent multivalue that breaks downstream logic. The detections in this repo use
`mvindex(IpAddress,0)` defensively regardless, so they keep working either way.
