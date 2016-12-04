Xxxcoin Core integration/staging tree
=====================================


(Website coming soon)
What is Xxxcoin?
----------------

Xxxcoin is an experimental digital currency developed for the adult industry, enabling instant payments to anyone, anywhere in the world. Xxxcoin uses peer-to-peer technology to operate with no central authority: managing transactions and issuing money are carried out collectively by the network. Xxxcoin Core is the name of open source software which enables the use of this currency.

License
-------

Xxxcoin Core is released under the terms of the MIT license. See COPYING for more information or see https://opensource.org/licenses/MIT.

Development Process
-------------------

The master branch is regularly built and tested, but is not guaranteed to be completely stable. Tags are created regularly to indicate new official, stable release versions of Xxxcoin Core.

The contribution workflow is described in [CONTRIBUTING.md](CONTRIBUTING.md).

The developer mailing list should be used to discuss complicated or controversial changes before working on a patch set.

Testing
-------

Testing and code review is the bottleneck for development; we get more pull requests than we can review and test on short notice. Please be patient and help out by testing other people's pull requests, and remember this is a security-critical project where any mistake might cost people lots of money.

### Manual Quality Assurance (QA) Testing

Changes should be tested by somebody other than the developer who wrote the code. This is especially important for large or high-risk changes. It is useful to add a test plan to the pull request description if testing the changes is not straightforward.

Translations
------------

We only accept translation fixes that are submitted through Bitcoin Core's Transifex page. Translations are converted to Xxxcoin periodically.

Translations are periodically pulled from Transifex and merged into the git repository. See the translation process for details on how this works.

**Important**: We do not accept translation changes as GitHub pull requests because the next pull from Transifex would automatically overwrite them again.
