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

import {
  AnsibleIcon,
  AWSIcon,
  AzureIcon,
  CircleCIIcon,
  GCPIcon,
  GitHubIcon,
  GitLabIcon,
  JenkinsIcon,
  KubernetesIcon,
  ServersIcon,
  SpaceliftIcon,
} from 'design/SVGIcon';
import { Box, Flex, Link as ExternalLink, Text } from 'design';
import { Link } from 'react-router-dom';
import React from 'react';

import {
  IntegrationEnrollEvent,
  IntegrationEnrollKind,
  userEventService,
} from 'teleport/services/userEvent';

import { IntegrationTile } from '../common';
import { ConfigureBot } from './GitHub';
import cfg from 'teleport/config';
import { IntegrationKind } from 'teleport/services/integrations';
import { GitHubActionsFlow } from './GitHub/EnrollMachineIdGitHub';

interface Integration {
  title: string;
  link: string;
  icon: JSX.Element;
  kind: IntegrationEnrollKind;
  guided: boolean;
}


const integrations: Integration[] = [
  GitHubActionsFlow,
  {
    title: 'CircleCI',
    link: 'https://goteleport.com/docs/machine-id/deployment/circleci/',
    icon: <CircleCIIcon size={80} />,
    kind: IntegrationEnrollKind.MachineIDCircleCI,
    guided: false,
  },
  {
    title: 'GitLab CI/CD',
    link: 'https://goteleport.com/docs/machine-id/deployment/gitlab/',
    icon: <GitLabIcon size={80} />,
    kind: IntegrationEnrollKind.MachineIDGitLab,
    guided: false,
  },
  {
    title: 'Jenkins',
    link: 'https://goteleport.com/docs/machine-id/deployment/jenkins/',
    icon: <JenkinsIcon size={80} />,
    kind: IntegrationEnrollKind.MachineIDJenkins,
    guided: false,
  },
  {
    title: 'Ansible',
    link: 'https://goteleport.com/docs/machine-id/access-guides/ansible/',
    icon: <AnsibleIcon size={80} />,
    kind: IntegrationEnrollKind.MachineIDAnsible,
    guided: false,
  },
  {
    title: 'Spacelift',
    link: 'https://goteleport.com/docs/machine-id/deployment/spacelift/',
    icon: <SpaceliftIcon size={80} />,
    kind: IntegrationEnrollKind.MachineIDSpacelift,
    guided: false,
  },
  {
    title: 'AWS',
    link: 'https://goteleport.com/docs/machine-id/deployment/aws/',
    icon: <AWSIcon size={80} />,
    kind: IntegrationEnrollKind.MachineIDAWS,
    guided: false,
  },
  {
    title: 'GCP',
    link: 'https://goteleport.com/docs/machine-id/deployment/gcp/',
    icon: <GCPIcon size={80} />,
    kind: IntegrationEnrollKind.MachineIDGCP,
    guided: false,
  },
  {
    title: 'Azure',
    link: 'https://goteleport.com/docs/machine-id/deployment/azure/',
    icon: <AzureIcon size={80} />,
    kind: IntegrationEnrollKind.MachineIDAzure,
    guided: false,
  },
  {
    title: 'Kubernetes',
    link: 'https://goteleport.com/docs/machine-id/deployment/kubernetes/',
    icon: <KubernetesIcon size={80} />,
    kind: IntegrationEnrollKind.MachineIDKubernetes,
    guided: false,
  },
  {
    title: 'Generic',
    link: 'https://goteleport.com/docs/machine-id/getting-started/',
    icon: <ServersIcon size={80} />,
    kind: IntegrationEnrollKind.MachineID,
    guided: false,
  },
];

export const MachineIDIntegrationSection = () => {
  return (
    <>
      <Box mb={3}>
        <Text fontWeight="bold" typography="h4">
          Machine ID
        </Text>
        <Text typography="body1">
          Set up Teleport Machine ID to allow CI/CD workflows and other machines
          to access resources protected by Teleport.
        </Text>
      </Box>
      <Flex mb={2} gap={3} flexWrap="wrap">
        {integrations.map(i =>
          <Box key={i.title}>
            {i.guided ? <GuidedTile integration={i} /> : <ExternalLinkTile integration={i} />}
          </Box>
        )}
      </Flex>
    </>
  );
};

function ExternalLinkTile({ integration }: { integration: Integration }) {
  return (<IntegrationTile
    as={ExternalLink}
    href={integration.link}
    target="_blank"
    onClick={() => {
      userEventService.captureIntegrationEnrollEvent({
        event: IntegrationEnrollEvent.Started,
        eventData: {
          id: crypto.randomUUID(),
          kind: integration.kind,
        },
      });
    }}
  >
    <TileContent icon={integration.icon} title={integration.title} />
  </IntegrationTile>)
}

function GuidedTile({ integration }: { integration: Integration }) {
  // TODO guided badge
  return (<IntegrationTile
    as={Link}
    to={integration.link}
  // TODO: route
  // onClick={() => {
  //   userEventService.captureIntegrationEnrollEvent({
  //     event: IntegrationEnrollEvent.Started,
  //     eventData: {
  //       id: crypto.randomUUID(),
  //       kind: integration.kind,
  //     },
  //   });
  // }}
  >
    <TileContent icon={integration.icon} title={integration.title} />
  </IntegrationTile >)
}

function TileContent({ icon, title }) {
  return (
    <>
      <Box mt={3} mb={2}>
        {icon}
      </Box>
      <Text>{title}</Text>
    </>)
}