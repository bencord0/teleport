/**
 * Copyright 2022 Gravitational, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import React from 'react';
import styled from 'styled-components';
import { ButtonPrimary, Text, Flex, ButtonSecondary, Image } from 'design';

import cfg from 'teleport/config';
import history from 'teleport/services/history';

import celebratePamPng from './celebrate-pam.png';

import type { AgentStepProps } from '../../types';

export function Finished(props: AgentStepProps) {
  if (props.agentMeta.autoDiscovery) {
    return (
      <Container>
        <Image width="120px" height="120px" src={celebratePamPng} />
        <Text mt={3} mb={2} typography="h4" bold>
          Completed Setup
        </Text>
        <Text mb={3}>You have completed setup for auto-enrolling.</Text>
        <Flex>
          <ButtonPrimary
            width="270px"
            size="large"
            onClick={() => history.push(cfg.routes.root, true)}
            mr={3}
          >
            Browse Existing Resources
          </ButtonPrimary>
          <ButtonSecondary
            width="270px"
            size="large"
            onClick={() => history.reload()}
          >
            Add Another Resource
          </ButtonSecondary>
        </Flex>
      </Container>
    );
  }

  let resourceText;
  if (props.agentMeta && props.agentMeta.resourceName) {
    resourceText = `Resource [${props.agentMeta.resourceName}] has been successfully added to
        this Teleport Cluster.`;
  }

  return (
    <Container>
      <Image width="120px" height="120px" src={celebratePamPng} />
      <Text mt={3} mb={2} typography="h4" bold>
        Resource Successfully Added
      </Text>
      <Text mb={3}>
        {resourceText} You can start accessing this resource right away or add
        another resource.
      </Text>
      <Flex>
        <ButtonPrimary
          width="270px"
          size="large"
          onClick={() => history.push(cfg.routes.root, true)}
          mr={3}
        >
          Browse Existing Resources
        </ButtonPrimary>
        <ButtonSecondary
          width="270px"
          size="large"
          onClick={() => history.reload()}
        >
          Add Another Resource
        </ButtonSecondary>
      </Flex>
    </Container>
  );
}

const Container = styled(Flex)`
  width: 600px;
  flex-direction: column;
  align-items: center;
  margin: 0 auto;
  text-align: center;
`;
