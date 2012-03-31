
  // curlish - curl with flames on top

                        .('
                       /%/\\'
                      (%(%))'
                       curl'

    Ever had to speak to an OAuth 2.0 protected
    resource for debugging purposes?  curl is a
    nice tool, but it totally lacks helpers for
    dealing with oauth.

    curlish comes for the rescue.  It is able to
    remember access tokens for you and inject it
    into requests.

    Facebook is preconfigured so that you can dive
    into testing it:

    $ curlish https://graph.facebook.com/me

    To add more sites you can directly modify the
    config file which is located, conveniently
    in ~/.ftcurlish.json

    Requirements: Python 2.6 or higher.

    Full automated installation:

    $ curl -L http://bit.ly/curlish | bash

    Installs curlish into ~/.bin for you.

    (If you want to know what it executes, have a
    look at the install.sh file in this repo)

    For advanced use see the ~/.ftcurlish.json file
    which can be used to automatically add extra
    headers to all requests and more.  You can
    also use the thing with non OAuth endpoints
    by just not configuring OAuth.  Then it just
    injects extra headers and colorizes output.

