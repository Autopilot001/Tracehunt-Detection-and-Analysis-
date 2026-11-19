# Trace Signal Detection and Analysis

## Focus

I traced a suspicious sign-in through the phishing email and mailbox changes, then checked how widely the campaign reached.

## Detection

### Find the unusual sign-ins

I began with the affected account's Entra ID sign-in events. I compared the time, source address, location, application, and authentication result so I could separate expected activity from successful sign-ins that needed a closer look. The results pointed to unusual successful sign-ins from Amsterdam.

```spl
index=ir sourcetype=azure:aad:signin userPrincipalName="l.chen@nexusfinancial.thm"
NOT ipAddress="[CORPORATE_IP]"
status.errorCode=0
| sort _time
| table _time ipAddress location.city location.countryOrRegion
```

<details><summary>Screenshot 1 — Sign-in activity</summary>

![Sign-in activity](../screenshots/step-01.png)

</details>

### Trace the email that arrived before the sign-in

Next I checked message-trace records for Laura Chen. I sorted the delivered messages by time and compared the sender, subject, source, and delivery status. One unfamiliar message stood out because it arrived shortly before the suspicious activity.

```spl
index=ir sourcetype=o365:reporting:messagetrace RecipientAddress="l.chen@nexusfinancial.thm"
| table Received SenderAddress Subject FromIP Status
| sort Received
```

<details><summary>Screenshot 2 — Message trace and subject</summary>

![Message trace and subject](../screenshots/step-02.png)

</details>

### Confirm the sender domain

I narrowed the message-trace results to the sender and recipient fields. That confirmed the suspicious message came from an external lookalike domain, which I treated as an indicator for the rest of the investigation.

```spl
index=ir sourcetype=o365:reporting:messagetrace RecipientAddress="l.chen@nexusfinancial.thm"
| table SenderAddress Subject Received
```

<details><summary>Screenshot 3 — Sender domain</summary>

![Sender domain](../screenshots/step-03.png)

</details>

## Analysis

### Check how many accounts used the same source

I searched sign-in events for the suspicious source and counted distinct user accounts. The results showed that the activity affected more than one account.

```spl
index=ir sourcetype=azure:aad:signin ipAddress="[ATTACKER_IP]"
| stats dc(userPrincipalName) as CompromisedAccounts
```

<details><summary>Screenshot 4 — Distinct affected accounts</summary>

![Distinct affected accounts](../screenshots/step-04.png)

</details>

### Identify the other affected account

I listed the unique account names associated with that source to see which users were involved. This connected the original report to a second account in the same environment.

```spl
index=ir sourcetype=azure:aad:signin ipAddress="[ATTACKER_IP]"
| dedup userPrincipalName
| table userPrincipalName
```

<details><summary>Screenshot 5 — Accounts in the sign-in results</summary>

![Accounts in the sign-in results](../screenshots/step-05.png)

</details>

### Look for mailbox persistence

I pivoted to the Microsoft 365 audit events and searched for a new inbox rule on Laura Chen's account. The result showed a rule that could hide messages from the user, so I included it as a persistence finding.

```spl
index=ir sourcetype=o365:management:activity UserId="l.chen@nexusfinancial.thm"
Operation="New-InboxRule"
| table _time Name ClientIP
```

<details><summary>Screenshot 6 — New inbox rule</summary>

![New inbox rule](../screenshots/step-06.png)

</details>

### Measure the phishing campaign's reach

To finish, I counted distinct recipients of messages from the identified sender. That gave me a quick measure of how many employees received the initial phishing email, beyond the accounts that later showed suspicious sign-ins.

```spl
index=ir sourcetype=o365:reporting:messagetrace SenderAddress="hr-support@nexus-verify.thm"
| stats dc(RecipientAddress)
```

<details><summary>Screenshot 7 — Distinct email recipients</summary>

![Distinct email recipients](../screenshots/step-07.png)

</details>


Correlating identity, mail, and audit events helped me build a clearer timeline than reviewing each source on its own.


I would alert on unusual successful sign-ins, unexpected inbox-rule creation, and phishing messages sent to multiple employees.
