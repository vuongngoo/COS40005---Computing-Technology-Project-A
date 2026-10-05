## COS40005 - Computing Technology Project A

**Group 7** 

**Semester:** September - November 2026

**Supervisor Meeting Session:** 8:00 - 12:00 Thursday

---

### Group Information:
1. Member 1: **Ngo Sy Vuong** [Project Manager + AI lead] - ID: 105551480
3. Member 2: **Giang Ngoc Vu** [Frontend Developer] - ID: 105551587
4. Member 3: **Tran Duc Minh** [Full stack + Cybersecurity support] - ID: 105543843
5. Member 4: **Nguyen Hoang Phuc Anh** [Backend Developer] - ID: 105551545
6. Member 5: **Nguyen Duy Hoang** [CyberSecurity lead] - ID: 105551448 

### Primary Contact:
Please contact our group leader via Email or Phone:
- Email: ***ngosyvuong15022006@gmail.com***
- Phone: ***0964753944***

### Group Tools:
- **Github:** [Source code and Project Management](https://github.com/vuongngoo/COS40005---Computing-Technology-Project-A)
- **Google Doc:** [Reports and Forms](https://docs.google.com/document/d/1LSULFDJQ5SirWlNIa1bi7qAtlYH97PtKeu0K9opfWWM/edit?usp=sharing)
- **Google Drive:** Will be provided if needed
- **Messenger:** Group chat
- **Discord:** Weekly Meetings

---

## CAP-07: Detection-as-Code: Engineering, Testing, and Validating Cybersecurity Detections

### Research Question

Can cybersecurity detections be developed and maintained using reproducible software-engineering practices such as version control, automated testing, peer review, and CI/CD?

---

### Indicative Outcome

A version-controlled Detection-as-Code repository with automated validation, ATT&CK mapping, test evidence, and repeatable engineering standards for security detections.

---

### Description

Security detection rules are often created manually and deployed directly into security platforms, making them difficult to review, test, maintain, and validate consistently.

Software-engineering practices such as version control, automated testing, continuous integration, peer review, and reproducible deployment can provide a more disciplined approach to detection development.

This project investigates a Detection-as-Code model in which security detections are treated as maintainable engineering artifacts: version-controlled, mapped to adversary behavior, automatically validated, and tested against controlled simulations.

---

### Scope

- Define a detection-engineering lifecycle from detection requirement through implementation, validation, review, and deployment.
- Develop Sigma and/or platform-specific detection rules with standardized metadata and MITRE ATT&CK mappings.
- Maintain detection content in a Git-based repository with version history and peer-review practices.
- Implement automated syntax validation, metadata checks, rule linting, and quality gates.
- Integrate controlled attack simulation or representative test data to determine whether expected detections succeed.
- Introduce regression testing to reduce the risk that future changes break previously validated detections.
- Produce automated pass/fail results and a repeatable ATT&CK coverage report.
- Evaluate practical limitations, including false positives, data-source dependencies, platform differences, and test-environment constraints.

#### Scope / Safety Note

Attack simulations used for validation should be conducted only in isolated and authorized environments. The project should emphasize safe, reproducible testing rather than uncontrolled offensive activity.

---

### Suggested Evaluation Measures

1. **Rule validation pass rate:** Percentage of detection rules that pass syntax, metadata, and functional test gates.
2. **ATT&CK coverage:** Coverage of selected techniques by validated detection content.
3. **Regression stability:** Number of previously passing detections that fail after repository or platform changes.
4. **False-positive behavior:** Observed noise or benign triggers within representative test data.
5. **Pipeline repeatability:** Consistency of validation results across repeated executions and controlled environments.
6. **Engineering lead time:** Time required to move a detection from requirement to validated, reviewable artifact.

---

### Deliverables

1. Detection-as-Code repository
2. Detection engineering standards
   - Naming and metadata requirements
   - ATT&CK mapping conventions
   - Quality and review criteria
6. Detection rule library
7. Automated CI/CD validation pipeline
8. Attack-simulation or representative test suite
9. Automated pass/fail and regression testing capability
10. ATT&CK detection-coverage report
11. Technical documentation and operating guide
12. Final research report and live demonstration

---

### Project Skills

1. Security engineering
2. Git
3. SIEM platforms
4. Python / scripting
5. Security telemetry
6. Detection engineering
7. CI / CD
8. MITRE ATT&CK
9. Automation
10. Security architecture
11. DevSecOps
12. Sigma
13. Atomic Red Team
14. Software testing
15. Documentation

---

### References

- SigmaHQ - Sigma Rule Specification
- MITRE ATT&CK
- Atomic Red Team
- NIST Cybersecurity Framework 2.0
- Git / GitHub / GitLab documentation
- CI/CD platform documentation
- Relevant SIEM documentation

---

### Supervisors

#### Academic Supervisor

Van Dai Pham

dvpham@swin.edu.au

#### Industry Supervisor

ISC2 Vietnam Chapter / Mr.

robert.leyba@owasp.org

