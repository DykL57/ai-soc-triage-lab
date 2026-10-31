I'll inspect the 4769 data in win_dc first, then build and test both rules against your 11:17 test.

Only one 4769 in 30 days — that's your test event. Let me confirm the baseline across all time and other indexes, and check what other Kerberos events exist.

No hit — debugging the filters one at a time.

Found it: `IpAddress` is extracted twice here (multivalue), so `replace()` returned null and the `by src_ip` split silently dropped the event. Fixing with `mvindex` and re-testing.

Both rules are built and tested against your 11:17 test. **Rule 1 (RC4) fires on it and is the higher-fidelity rule here.** Rule 2 is mechanically correct, but at a sensible threshold it would *not* fire on your test, for the reasons below.

## What the data showed

- **4769 baseline is essentially zero.** Your test event (11:17:49) is the only 4769 ever indexed in `win_dc`. 4768 has 30 days of history (714 events), but no service-ticket events at all. That means auditing was turned on at about the time you tested. Even several minutes later, no normal machine-account 4769s had arrived, and in a working domain those show up constantly. Run `auditpol /get /subcategory:"Kerberos Service Ticket Operations"` on DC01 and confirm benign 4769s start flowing before you trust either rule.
- **Encryption types:** every 4768 is AES256 (`0x12`) across all 9 accounts. The only RC4 (`0x17`) ticket in the data is your attack, so this domain's normal behaviour is all AES.
- **Field formats:** `TargetUserName` holds the requester as `bob.user@LAB.LOCAL`. `ServiceName` holds the target (`svc_sql`). `IpAddress` is `::ffff:10.0.30.100`.
- **One bug found while testing:** `IpAddress` is extracted twice here, so it's multivalue. A plain `replace()` returns null, and `stats ... by src_ip` silently drops the event. My first draft missed your test because of this. Both rules below use `mvindex(IpAddress,0)`. The same issue could hide events in other searches on this index, so it's worth fixing the duplicate extraction.
- **Full attack chain is visible:** Administrator ran `setspn -a MSSQL/db01.lab.local:1433 svc_sql` at 11:16:00. Then `setspn -T lab.local -Q */*` ran on WIN-CL01 at 11:17:40, and the RC4 ticket was issued to 10.0.30.100 nine seconds later.

## Rule 1: RC4 service ticket for a user SPN account

```spl
index=win_dc EventCode=4769 Status=0x0 TicketEncryptionType=0x17
| eval service=lower(ServiceName),
       requester=lower(mvindex(split(TargetUserName,"@"),0)),
       src_ip=replace(mvindex(IpAddress,0),"^::ffff:","")
| where NOT match(service,"\$$") AND service!="krbtgt" AND NOT like(service,"krbtgt/%")
| where NOT match(requester,"\$$")
| fillnull value="unknown" src_ip
| stats min(_time) as firstTime max(_time) as lastTime count
        values(service) as services dc(service) as spn_count
        values(TicketOptions) as ticket_options by requester src_ip
| convert ctime(firstTime) ctime(lastTime)
```

Schedule it every 5 min with `earliest_time=-10m@m`, `latest_time=-5m@m`. The 5-minute lag absorbs forwarder delay.

**Tested on** 2026-10-31 00:00–12:00: 1 hit, `bob.user` from 10.0.30.100 → `svc_sql`, options `0x40810000`.

- **Keys on:** `TicketEncryptionType=0x17`, `Status=0x0`, `ServiceName` (excluding `$` accounts, which also covers gMSAs, and krbtgt), and the requester from `TargetUserName` (excluding `$`).
- **Threshold: 1 event.** Every Kerberos ticket in this domain is AES, so a single successful RC4 ticket for a user SPN is already abnormal. No count is needed.
- **Expected false positives:**
  - Service accounts with no AES keys, usually because the password predates the 2008 domain functional level.
  - Accounts with `msDS-SupportedEncryptionTypes` set to RC4.
  - Legacy, Java or Linux keytab clients, and cross-forest trusts.
- **Tuning:** the right fix is to give the account AES (reset its password and set its supported encryption types) rather than suppress the alert. Allowlist a specific requester and service pair only after you've reviewed it.
- **Blind spot:** an attacker who requests AES gets no RC4 ticket, and neither does one roasting an account that supports only AES. This rule never sees either case.

## Rule 2: one account requesting many distinct SPNs, any encryption type

```spl
index=win_dc EventCode=4769 Status=0x0
| eval service=lower(ServiceName),
       requester=lower(mvindex(split(TargetUserName,"@"),0)),
       src_ip=replace(mvindex(IpAddress,0),"^::ffff:","")
| where NOT match(service,"\$$") AND service!="krbtgt" AND NOT like(service,"krbtgt/%")
| where NOT match(requester,"\$$")
| bin _time span=10m
| stats dc(service) as distinct_spns count as tickets values(service) as services
        values(TicketEncryptionType) as enc_types values(src_ip) as src_ips by _time requester
| eval rc4_present=if(isnotnull(mvfind(enc_types,"^0x17$")),"yes","no")
| where distinct_spns>=3
```

Schedule it every 10 min with `earliest_time=-20m@m`, `latest_time=-5m@m`, and dedupe on `requester`.

**Tested** with the threshold removed: the logic correctly groups your test into 1 distinct SPN, with `rc4_present=yes`. At `>=3` it does **not** fire. That's expected, because svc_sql is the only user SPN you've registered and you roasted one target.

- **Keys on:** the number of distinct user-account `ServiceName` values per requester in 10 minutes, regardless of encryption type.
- **Threshold: 3 or more distinct user SPNs in 10 min, to start with.** A normal user touches one or two service accounts, such as a SQL database or a web app. Tools like Rubeus or GetUserSPNs that roast everything ask for every SPN account within seconds. Excluding machine accounts matters most here, because ordinary logons request tickets for many `HOST$` and `CIFS$` services.
- **Thin baseline:** with no 4769 history, the 3 is an educated guess. Run the search without the `where` for 1–2 weeks, look at the per-user distribution, and set the threshold just above the 99th percentile. Also build an allowlist of known multi-service requesters.
- **Expected false positives:**
  - Admins and admin consoles (SSMS against several SQL instances, IIS management).
  - Monitoring and backup service accounts.
  - Vulnerability scanners and SCCM.
  - App servers doing delegation to several back ends.
- **Blind spots:** a single targeted roast like your test, attackers who throttle requests across longer windows, and small domains with fewer than 3 SPN accounts. Your lab is currently in that last category.

## Which is higher fidelity

**Rule 1**, in this environment. The domain is entirely AES, so an RC4 service ticket for a user account has almost no innocent explanation. It also caught your real test.

Rule 2 is the important backup, because it catches AES-based and mass roasting that Rule 1 can't see. But it will be noisier, it can't be tuned properly until you have 4769 history, and it misses single-target roasting.

Run both. When Rule 2 fires with `rc4_present=yes`, treat it as critical. For a cheap third signal, `setspn ... -Q */*` (or LDAP queries for `servicePrincipalName`) from a non-admin host was visible here 9 seconds before the ticket request.

I can save these as scheduled alerts in Splunk, or add the setspn correlation as a third rule.