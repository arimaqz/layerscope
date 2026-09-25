# Jenkins pipeline example

This workflow saves a locally available container image as a synthetic CI archive, uploads it with retry duplicate suppression, waits for the persistent scan job, and fails the build when a `HIGH` or `CRITICAL` vulnerability is present.

Before using `Jenkinsfile`:

1. Give the agent Python 3.12+, Docker, and network access to LayerScope.
2. Create an operator account in LayerScope and create a short-lived personal API token from **API tokens**.
3. Store the secret as a Jenkins **Secret text** credential named `layerscope-api-token`.
4. Copy the example stages into the repository's pipeline and set `LAYERSCOPE_URL` and `IMAGE_REF` for the environment.

The credential is supplied only through Jenkins' masked environment binding. The workflow does not print or persist it. The JSON artifacts contain job and normalized scan summaries, not the token or the original archive. Consider the finding data private and apply the CI server's normal artifact access and retention controls.
