# Project completed as part of Carmela Troncoso's *Advanced Topics on Privacy-Enhancing Technologies* course at EPFL, summer term 2022

(Note: only parts 1 and 3 are included, as part 2 was completed by my group partner.)

Individual parts have more specific and detailed README-files in the respective subdirectories.

## Part I: Design an anonymous authentication protocol for a location-based service.

Implemented the Pointcheval-Sanders anonymous authentication scheme (see `part1/ABC-Guide.pdf` for details). 
The use case was an application providing users with points of interest in the vicinity of a given geographical location. Importantly, access to the service was granted upon presenting a valid anonymous credential (i.e., users prove their entitlement to use the service with a zero-knowledge-proof).

## Part II: Mount a fingerprinting attack on the Tor network.

This was a nice demonstration of the different layers of the network stack regarding privacy. Clearly, the crypto stuff implemented in part1 resides on the application layer. In a setting where the user queries POIs for certain locations from a server over the Tor network, we can use a fingerprinting technique to learn to identify the geographical grid a query pertains to (for simplication, in this part users were only able to query discrete location grids). I.e., we now only rely on network layer metadata to identify traffic patterns and match them to patterns we learned previously (supervised learning).

We used a random forest classifier for fingerprinting, as described in [Hayes & Danezis, 2016](https://www.usenix.org/sites/default/files/conference/protected-files/security16_slides_hayes.pdf). Heck, this type of attack seems to be outdated already - even higher accuracy for these types of attacks can be achieved by leveraging [Deep learning](https://dl.acm.org/doi/pdf/10.1145/3243734.3243768).