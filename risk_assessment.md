# Risk Assessment

## 1. Assets

### Asset 1: Student Records
The student records contain academic and personal information stored on the central server.

### Asset 2: Student Records Server
The central server stores and provides access to student records.

### Asset 3: Network Services
The network services allow authorised staff and campuses to access the student records system.

## 2. Vulnerabilities and Consequences

| Vulnerability | Possible Consequence |
|---|---|
| Weak staff passwords | Unauthorised users may gain access to accounts and student records. |
| Unencrypted file transfers | Student information may be intercepted during transmission. |
| Guest network access to the records server | Unauthorised users may access or attack the records server. |

## 3. Risk Ranking

| Risk | Likelihood | Impact | Reason |
|---|---|---|---|
| Weak staff passwords | High | High | Weak credentials can be easier to compromise and may provide access to sensitive records. |
| Unencrypted file transfers | Medium | High | Data transmitted without encryption may be exposed during transfer. |
| Guest access to records server | Medium | High | Unauthorised network users could attempt to access the records server. |

## 4. Recommended Controls

### Weak staff passwords
Implement strong password requirements and secure authentication practices.

### Unencrypted file transfers
Use encrypted communication for transferring student records.

### Guest network access
Use firewall rules and network segmentation to block guest access to the student records server.