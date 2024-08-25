---
layout: post
title: Threat Hunting
image: /assets/img/notes/ThreatHunting/threat.jpg
related_posts:
  - /notes/_posts/2024-08-15-IntroductionToIDSAndIPS.md
sitemap: false
categories: notes
---

# Threat Hunting

* toc
{:toc}

## Introduction

To understand in resumen what is a threat hunting, we can see the different steps of a incident response.

- `Preparation:` in this phase we need to ensure we have the correct steps or playbooks no establish a incident response. And threat hunters need to have protocols that let know where and how to interven.

- `Detection & Analysis:` In this step, threat hunters are crucial tu know about `IOC (Indicator of Compromise)`. They can cover more assets that could be compromise and have not been detected.

- `Containment, Eradication, Recovery:` This steps is more for incident responders, some organizations used threat hunbers to do this step.

- `Post-Incident Activity:` Threat hunters can give recomendations to enhancing security.

Threat Intelligent is part of this group that makes investigations un darkweb, forums, about new advanced `TTP (Tecniques, Tactics And Procedures)` that hackers can use against de organization.

## Threat Hunting Process

`Setting the Stage:` In this step we have an objective, like a malware that recently was discovered, with Threat Intelligence about `IOC (Indicators of Compromise)` about this malware. We need to know our principal assets that could be potentially objectives.
`Formulating Hypotheses:` After gathering some information about this new malware, we need to make an hyphoteses about how this malware gonna work, for example, we need to know `TTP (Techinques, Tactics and Procedures)` of this malware, the first insight could be phishing and then establish a connection with a reverse shell or `C2`.
`Designing the Hunt:` At this point we have to make some, rules, filters, tests to accept or not our hyphoteses. We can use `SIEM` tools, `sandboxes`, `IDS/IPS` tools. We can gather information of `Threat Intelligence` to make this step.
`Data Gathering and Examination:` This is the first active step of `Threat Hunting`, we need to take our hunt desing in action. We make all the search, filters, procedures to know if theres a threat in the system. 
`Evaluating Findings and Testing Hypotheses:` This step is about accept or not hypothesis based in `Data Gathering Step`, the team should evaluate each possible `TTP` seen in `Formulating Hypothesis` step.
`Mitigating Threats:` The team need to erradicate de threat, isolate compromised machines, make patches or configure network rules.
`After the Hunt:` Improve all situation possible based in all the step. Updating playbooks, rules, alerts, etc.
`Continuous Learning and Enhancement:` Continue improving knowledge of each step about similar threat that are gonna fight.


### Pyramid of pain

![image1](/assets/img/notes/ThreatHunting/threat1.jpg){:.lead width="800" height="100" loading="lazy"}


### Diamond 

![image1](/assets/img/notes/ThreatHunting/threat2.jpg){:.lead width="800" height="100" loading="lazy"}


