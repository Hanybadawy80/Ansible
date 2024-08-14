#### What's Improved
- Added a new action `Send Email (Advanced)` which can send email using FortiSOAR email template.
- Added a new parameter, `Save Email` to support storing the email in a FortiSOAR attachment for the 'Search Email' action.
- Updated data ingestion configuration.
- Updated the Python dependencies for the connector with the following requirements:
  - exchangelib version must be 5.4.0 or higher
  - dnspython version must be 2.3.0 or higher
- Removed `Convert Inline Images to Attachments` parameter and updated output schemas of following actions:
  - Get Unread Emails
  - Search Email

#### What's Fixed
- Fixed a bug where listeners activated with test configuration during connector development using BYOC should be deactivated.
- Fixed a bug where connector health check was failing with the error `module 'dns.resolver' has no attribute 'LifetimeTimeout' ERROR module 'dns.resolver' has no attribute 'LifetimeTimeout'`
- Fixed a bug where connector actions was failed with error `with error "Tried versions ('Exchange2016', 'Exchange2015_SP1', 'Exchange2015', 'Exchange2013_SP1', 'Exchange2013', 'Exchange2010_SP2', 'Exchange2010_SP1', 'Exchange2010', 'Exchange2007_SP1', 'Exchange2007') but all were invalid"` for  on-prem exchange server.
>**_NOTE:_** After upgrading the connector, you must restart the uwsgi service.`
- Fixed issue for notification service. Emails were not getting ingesting when they were marked as unread email.