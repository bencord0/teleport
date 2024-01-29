/**
 * Teleport
 * Copyright (C) 2023  Gravitational, Inc.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

import React from 'react';

import Box from 'design/Box';
import Text from 'design/Text';
import TextEditor from 'shared/components/TextEditor';
import Flex from 'design/Flex';

import useTeleport from 'teleport/useTeleport';

import { FlowButtons } from '../Shared/FlowButtons';

import { FlowStepProps } from '../Shared/GuidedFlow';

import { useGitHubFlow } from './useGitHubFlow';

export function AddBotToWorkflow({ prevStep, nextStep }: FlowStepProps) {
  const { tokenName, createBotRequest } = useGitHubFlow();
  const ctx = useTeleport();
  const cluster = ctx.storeUser.state.cluster;

  const yaml = getWorkflowExampleYaml(
    createBotRequest.botName,
    cluster.authVersion,
    cluster.publicURL,
    tokenName
  );

  return (
    <Box mb="0">
      <Text bold fontSize={4} mb="3">
        Step 3: Connect Your Bot in a GitHub Actions Workflow
      </Text>
      <Text fontSize={3} mb="3">
        Teleport has created a role, a bot, and a join token. Below is an
        example GitHub Actions workflow doc to help you get started. You can
        find this again from the bot’s options dropdown
      </Text>
      <Flex flex="1" height="630px" maxWidth="840px" mb="3">
        <TextEditor
          readOnly={true}
          bg="levels.deep"
          data={[{ content: yaml, type: 'yaml' }]}
          copyButton={true}
          downloadButton={true}
          downloadFileName={`${createBotRequest.botName}-githubactions.yaml`}
        />
      </Flex>
      <FlowButtons
        nextStep={nextStep}
        prevStep={prevStep}
        backButton={{
          hidden: true,
        }}
      />
    </Box>
  );
}

function getWorkflowExampleYaml(
  botName: string,
  version: string,
  proxyAddr: string,
  tokenName: string
): string {
  return `on:
push:
  branches:
  - main
jobs:
demo:
  permissions:
    # The "id-token: write" permission is required or Machine ID will not be
    # able to authenticate with the cluster.
    id-token: write
    contents: read
  # if you added a workflow name in the previous step, make sure you use the same value here
  name: ${botName}-example
  runs-on: ubuntu-latest
  steps:
  - name: Checkout repository
    uses: actions/checkout@v3
  - name: Fetch Teleport binaries
    uses: teleport-actions/setup@v1
    with:
      version: ${version}
  # server access example
  - name: Fetch credentials using Machine ID
    id: auth
    uses: teleport-actions/auth@v2
    with:
      proxy: ${proxyAddr}
      token: ${tokenName}
      # Enable the submission of anonymous usage telemetry. This
      # helps us shape the future development of \`tbot\`. You can disable this
      # by omitting this.
      anonymous-telemetry: 1
  - name: List nodes (tsh)
    # Enters a command from the cluster, in this case "tsh ls" using Machine
    # ID credentials to list remote SSH nodes.
    run: tsh ls
  # kubernetes access example
  - name: Fetch kubectl
    uses: azure/setup-kubectl@v3
  - name: Fetch credentials using Machine ID
    uses: teleport-actions/auth-k8s@v2
    with:
      proxy: ${proxyAddr}
      token: ${tokenName}
      # Use the name of your Kubernetes cluster
      kubernetes-cluster: my-kubernetes-cluster
      anonymous-telemetry: 1
  - name: List pods
    run: kubectl get pods -A`;
}