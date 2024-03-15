#!/usr/bin/env python3
from . import SecretFinding


KNOWN_DOMAINS = [
    'gmail.com',
    'yahoo.com',
    'hotmail.com',
    'aol.com',
    'hotmail.co.uk',
    'hotmail.fr',
    'msn.com',
    'yahoo.fr',
    'wanadoo.fr',
    'orange.fr',
    'comcast.net',
    'yahoo.co.uk',
    'yahoo.com.br',
    'yahoo.co.in',
    'live.com',
    'rediffmail.com',
    'free.fr',
    'gmx.de',
    'web.de',
    'yandex.ru',
    'ymail.com',
    'libero.it',
    'outlook.com',
    'uol.com.br',
    'bol.com.br',
    'mail.ru',
    'cox.net',
    'hotmail.it',
    'sbcglobal.net',
    'sfr.fr',
    'live.fr',
    'verizon.net',
    'live.co.uk',
    'googlemail.com',
    'yahoo.es',
    'ig.com.br',
    'live.nl',
    'bigpond.com',
    'terra.com.br',
    'yahoo.it',
    'neuf.fr',
    'yahoo.de',
    'alice.it',
    'rocketmail.com',
    'att.net',
    'laposte.net',
    'facebook.com',
    'bellsouth.net',
    'yahoo.in',
    'hotmail.es',
    'charter.net',
    'yahoo.ca',
    'yahoo.com.au',
    'rambler.ru',
    'hotmail.de',
    'tiscali.it',
    'shaw.ca',
    'yahoo.co.jp',
    'sky.com',
    'earthlink.net',
    'optonline.net',
    'freenet.de',
    't-online.de',
    'aliceadsl.fr',
    'virgilio.it',
    'home.nl',
    'qq.com',
    'telenet.be',
    'me.com',
    'yahoo.com.ar',
    'tiscali.co.uk',
    'yahoo.com.mx',
    'voila.fr',
    'gmx.net',
    'mail.com',
    'planet.nl',
    'tin.it',
    'live.it',
    'ntlworld.com',
    'arcor.de',
    'yahoo.co.id',
    'frontiernet.net',
    'hetnet.nl',
    'live.com.au',
    'yahoo.com.sg',
    'zonnet.nl',
    'club-internet.fr',
    'juno.com',
    'optusnet.com.au',
    'blueyonder.co.uk',
    'bluewin.ch',
    'skynet.be',
    'sympatico.ca',
    'windstream.net',
    'mac.com',
    'centurytel.net',
    'chello.nl',
    'live.ca',
    'aim.com',
    'bigpond.net.au',
    'online.de',
]


class EMail(SecretFinding):
    name = 'EMail Address'

    description = [
        'An email address is a unique identifier that allows individuals or organizations to send and receive electronic messages over the internet. Email addresses are fundamental components of online communication, enabling not just the exchange of messages but also the registration and verification of users for various online services, platforms, and applications.',
        'Searching for email addresses in code is crucial to prevent the exposure of personal information. Email addresses embedded in publicly accessible code can not only compromise the privacy of individuals associated with the development process but also indicate a broader exposure of customer personal information. Such exposures make the information susceptible to phishing, spam, and targeted cyber-attacks.'
    ]

    patterns = [
        # This should catch patterns for things like "root@example.org"
        r'(?i)([a-z0-9\-\+\.]{2,})@(([a-z0-9\-\.]+)\.([a-z]{2,}))',
    ]

    ideal_rating = 3

    @classmethod
    def get_indicators(this, context, capture, capture_start, capture_end, groups):
        indicators = super().get_indicators(context, capture, capture_start, capture_end, groups)

        user, domain, sld, tld = groups

        try:
            domain = domain.decode()

            if domain.lower() in KNOWN_DOMAINS:
                indicators.append(('Address domain is known', 1))
            else:
                indicators.append(('Address domain is not known', -0.25))
        except:
            indicators.append(('Address domain could not be decoded', -1))

        return indicators


FINDINGS = [EMail]
