---
title: "The Carnot Bound"
description: "Recently, we released a paper called The Carnot Bound, which investigates the fundamental limits and possibilities for bandwidth-efficient consensus. The paper establishes a tight lower bound on coding efficiency for protocols with fast finality, and shows that an additional round of voting breaks the barrier."
date: "March 20th, 2026"
published-time: "2026-03-20T00:00:00Z"
modified-time: "2026-03-20T00:00:00Z"
author: "Andrew Lewis-Pye"
author_twitter: "https://x.com/AndrewLewisPye"
url: "https://commonware.xyz/blogs/carnot-bound"
image: "https://commonware.xyz/imgs/carnot.png"
katex: true
---

Recently, we released a paper called [The Carnot Bound](https://arxiv.org/abs/2603.11797), which investigates the fundamental limits and possibilities for bandwidth-efficient consensus. The paper establishes a tight lower bound on coding efficiency for protocols with fast finality, and shows that an additional round of voting breaks the barrier. Here's the idea.

In leader-based consensus, the leader is the throughput bottleneck. Every block the leader proposes must be sent to every other processor, and the time this takes is governed by a key parameter: the *data expansion rate*. If a block payload has size $\beta$, and the leader must send a total of $d \cdot \beta$ bits across all processors, then $d$ is the data expansion rate. The closer $d$ is to $1$, the closer maximum throughput gets to the raw network bandwidth.

Erasure coding is what makes $d < n$ possible. Rather than sending a full copy of the block to each of the $n$ processors, the leader encodes the payload into $n$ fragments, each much smaller than the original, from which the full payload can be reconstructed once enough fragments are collected. The question is: how small can $d$ actually get?

## A wall at 2.5

The answer depends on how many rounds of communication your protocol needs to finalise a block. Protocols with *2-round finality*---one round for the leader's proposal, one round of voting---include [E-Minimmit](https://arxiv.org/abs/2508.10862) and [Kudzu](https://arxiv.org/abs/2505.08771). These protocols achieve data expansion rates of roughly $2.5$. In the paper, we prove this is optimal: no protocol with 2-round finality can do better. The bound is tight.

The impossibility is established via an indistinguishability argument. In a protocol with 2-round finality, if the leader crashes immediately after sending fragments to a subset of processors, those processors must still be able to determine the leader's proposal. This forces enough redundancy in the leader's messages that the data expansion rate cannot drop below $2.5$.

## Breaking through with a second vote

Protocols with *3-round finality*---one proposal round and two rounds of voting---can circumvent this bound entirely, pushing the data expansion rate arbitrarily close to $1$. The key insight is that the second voting round provides a recovery mechanism. A leader can *attempt* an aggressive erasure code, and if some processors fail to reconstruct the payload, the second round detects this and allows the protocol to nullify the view and retry. With only one round of voting, a failed reconstruction attempt can leave the protocol in an unrecoverable state. With two rounds, it cannot.

We present two protocols realising this approach, both building on [Simplex](https://link.springer.com/chapter/10.1007/978-3-031-48624-1_17). **Carnot 1** assumes $n \geq 4f+1$ processors and achieves a particularly clean design: processors echo their fragment once upon voting, and no further fragment dissemination is ever required.

![](/imgs/carnot-algo-1.png)

**Carnot 2** operates under the optimal assumption $n \geq 3f+1$, at the cost of additional fragment dissemination when Byzantine processors interfere.

![](/imgs/carnot-algo-3.png)

![](/imgs/carnot-algo-4.png)

Under favourable conditions---correct leaders and few actual faults---both protocols allow data expansion rates approaching $1$. When conditions deteriorate, they revert to safe rates of roughly $1.33$ and $1.5$, respectively. Both rates are well below the $2.5$ wall for 2-round protocols.

Both protocols can also incorporate stable leaders and optimistic proposals, eliminating the gap between consecutive block proposals and allowing throughput to approach the underlying network bandwidth.

![](/imgs/carnot-algo-2.png)

The paper is available on [arXiv](https://arxiv.org/abs/2603.11797). The name is inspired by the Carnot heat engine, which achieves the theoretical maximum efficiency for converting heat into work. Similarly, our protocols aim to approach the theoretical maximum efficiency for converting network bandwidth into throughput.
