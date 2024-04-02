[![Deploy Detection Rules](https://github.com/bradleyjlevine/elastic-detection-rules-public/actions/workflows/deploy_detection_rules.yml/badge.svg)](https://github.com/bradleyjlevine/elastic-detection-rules-public/actions/workflows/deploy_detection_rules.yml)

### Start
You will need to add GitHub secrets that match the ones in the `.github/workflows/deploy_detection_rules.yml`:
- `${{ secrets.ELASTIC_API_KEY }}`
  - encoded value for API Key
- `${{ secrets.KIBANA_HOST }}`
  - `host:port` (9243 for Elastic Cloud)

### Triggers for CD
The workflow is triggered by push to main for changes in toml or json files on the paths below:
- `detection-rules/**/*.toml`
- `detection-rules/**/*.json`

At the end of the workflow it will do a commit/push with `[skip ci]`.  This will prevent the workflow from being triggered again.

You will need to go to your repos Settings > Actions > Gerneral:
1. Set _Workflow permissions_ to ***Read and write permissions***

### Important Scripts
The `rule_id` is automatically generated if not present in toml or json detection rule:
- `development/dr-validator.py`
  - This will run checks for required fields and types depending on the detection rule type
- `development/dr-update.py`
  - This will either update the existing detection rule or create a new one

### AWS Runner (self-hosted) - Optional
1. Update line 15 to self-hosted
   - You will need to install a runner on a EC2 Instance
2. Uncomment lines 25 - 35 to get your credentials from AWS Secrets Manager using the Instance Role on your runner.
3. Add new secret for `${{ secrets.AWS_SM_ARN }}` this is the ARN for the Secret

<br>

<a rel="license" href="http://creativecommons.org/licenses/by-sa/4.0/"><img alt="Creative Commons License" style="border-width:0" src="https://i.creativecommons.org/l/by-sa/4.0/88x31.png" /></a><br />This work is licensed under a <a rel="license" href="http://creativecommons.org/licenses/by-sa/4.0/">Creative Commons Attribution-ShareAlike 4.0 International License</a>.
