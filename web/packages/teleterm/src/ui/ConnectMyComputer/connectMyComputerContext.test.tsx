/**
 * Copyright 2023 Gravitational, Inc
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import { EventEmitter } from 'node:events';

import React from 'react';
import { act, renderHook, waitFor } from '@testing-library/react';
import { makeErrorAttempt } from 'shared/hooks/useAsync';

import { MockAppContextProvider } from 'teleterm/ui/fixtures/MockAppContextProvider';
import { MockAppContext } from 'teleterm/ui/fixtures/mocks';
import { WorkspaceContextProvider } from 'teleterm/ui/Documents';
import { AgentProcessState } from 'teleterm/mainProcess/types';
import * as resourcesContext from 'teleterm/ui/DocumentCluster/resourcesContext';
import {
  makeLoggedInUser,
  makeRootCluster,
  makeServer,
} from 'teleterm/services/tshd/testHelpers';

import {
  AgentCompatibilityError,
  AgentProcessError,
  ConnectMyComputerContextProvider,
  useConnectMyComputerContext,
} from './connectMyComputerContext';

import type { IAppContext } from 'teleterm/ui/types';
import type { Cluster } from 'teleterm/services/tshd/types';

function getMocks() {
  const rootCluster = makeRootCluster({
    loggedInUser: makeLoggedInUser({
      acl: {
        tokens: {
          create: true,
          edit: false,
          list: false,
          use: false,
          read: false,
          pb_delete: false,
        },
      },
    }),
  });
  const appContext = new MockAppContext({
    appVersion: rootCluster.proxyVersion,
  });

  appContext.clustersService.setState(draftState => {
    draftState.clusters.set(rootCluster.uri, rootCluster);
  });
  appContext.workspacesService.setState(draftState => {
    draftState.rootClusterUri = rootCluster.uri;
    draftState.workspaces[rootCluster.uri] = {
      documents: [],
      location: undefined,
      localClusterUri: rootCluster.uri,
      accessRequests: undefined,
    };
  });

  return { appContext, rootCluster };
}

function renderUseConnectMyComputerContextHook(
  appContext: IAppContext,
  rootCluster: Cluster
) {
  return renderHook(() => useConnectMyComputerContext(), {
    wrapper: ({ children }) => (
      <MockAppContextProvider appContext={appContext}>
        <WorkspaceContextProvider value={null}>
          <resourcesContext.ResourcesContextProvider>
            <ConnectMyComputerContextProvider rootClusterUri={rootCluster.uri}>
              {children}
            </ConnectMyComputerContextProvider>
          </resourcesContext.ResourcesContextProvider>
        </WorkspaceContextProvider>
      </MockAppContextProvider>
    ),
  });
}

test('startAgent re-throws errors that are thrown while spawning the process', async () => {
  const { appContext, rootCluster } = getMocks();
  const eventEmitter = new EventEmitter();
  const errorStatus: AgentProcessState = {
    status: 'error',
    message: 'ENOENT',
  };

  jest
    .spyOn(appContext.connectMyComputerService, 'waitForNodeToJoin')
    .mockImplementation(
      // Hang until abort.
      (rootClusterUri, abortSignal) =>
        new Promise((resolve, reject) => abortSignal.addEventListener(reject))
    );
  jest
    .spyOn(appContext.mainProcessClient, 'getAgentState')
    .mockImplementation(() => errorStatus);
  jest
    .spyOn(appContext.connectMyComputerService, 'runAgent')
    .mockImplementation(async () => {
      // the error is emitted before the function resolves
      eventEmitter.emit('', errorStatus);
      return;
    });
  jest
    .spyOn(appContext.mainProcessClient, 'subscribeToAgentUpdate')
    .mockImplementation((rootClusterUri, listener) => {
      eventEmitter.on('', listener);
      return { cleanup: () => eventEmitter.off('', listener) };
    });

  const { result } = renderUseConnectMyComputerContextHook(
    appContext,
    rootCluster
  );

  let error: Error;
  await act(async () => {
    [, error] = await result.current.startAgent();
  });
  expect(result.current.currentAction).toStrictEqual({
    kind: 'start',
    attempt: makeErrorAttempt(new AgentProcessError()),
    agentProcessState: {
      status: 'error',
      message: 'ENOENT',
    },
  });
  expect(error).toBeInstanceOf(AgentProcessError);
});

test('starting the agent flips the workspace autoStart flag to true', async () => {
  const { appContext, rootCluster } = getMocks();

  jest
    .spyOn(appContext.connectMyComputerService, 'waitForNodeToJoin')
    .mockResolvedValue(makeServer());

  const { result } = renderUseConnectMyComputerContextHook(
    appContext,
    rootCluster
  );

  await act(async () => {
    const [, error] = await result.current.startAgent();
    expect(error).toBeFalsy();
  });

  expect(
    appContext.workspacesService.getConnectMyComputerAutoStart(rootCluster.uri)
  ).toBe(true);
});

test('killing the agent flips the workspace autoStart flag to false', async () => {
  const { appContext, rootCluster } = getMocks();

  const { result } = renderUseConnectMyComputerContextHook(
    appContext,
    rootCluster
  );

  await act(() => result.current.killAgent());

  expect(
    appContext.workspacesService.getConnectMyComputerAutoStart(rootCluster.uri)
  ).toBe(false);
});

test('failed autostart flips the workspace autoStart flag to false', async () => {
  const { appContext, rootCluster } = getMocks();

  let currentAgentProcessState: AgentProcessState = {
    status: 'not-started',
  };
  jest
    .spyOn(appContext.mainProcessClient, 'getAgentState')
    .mockImplementation(() => currentAgentProcessState);
  jest
    .spyOn(appContext.connectMyComputerService, 'isAgentConfigFileCreated')
    .mockResolvedValue(true);
  jest
    .spyOn(appContext.connectMyComputerService, 'downloadAgent')
    .mockRejectedValue(new AgentCompatibilityError('incompatible'));

  appContext.workspacesService.setConnectMyComputerAutoStart(
    rootCluster.uri,
    true
  );

  const { result } = renderUseConnectMyComputerContextHook(
    appContext,
    rootCluster
  );

  await waitFor(
    () =>
      result.current.currentAction.kind === 'download' &&
      result.current.currentAction.attempt.status === 'error'
  );

  expect(
    appContext.workspacesService.getConnectMyComputerAutoStart(rootCluster.uri)
  ).toBe(false);
});

test('starts the agent automatically if the workspace autoStart flag is true', async () => {
  const { appContext, rootCluster } = getMocks();

  const eventEmitter = new EventEmitter();
  let currentAgentProcessState: AgentProcessState = {
    status: 'not-started',
  };
  jest
    .spyOn(appContext.mainProcessClient, 'getAgentState')
    .mockImplementation(() => currentAgentProcessState);
  jest
    .spyOn(appContext.connectMyComputerService, 'isAgentConfigFileCreated')
    .mockResolvedValue(true);
  jest
    .spyOn(appContext.connectMyComputerService, 'runAgent')
    .mockImplementation(async () => {
      currentAgentProcessState = { status: 'running' };
      eventEmitter.emit('', currentAgentProcessState);
    });
  jest
    .spyOn(appContext.connectMyComputerService, 'waitForNodeToJoin')
    .mockResolvedValue(makeServer());
  jest.spyOn(appContext.connectMyComputerService, 'downloadAgent');
  jest
    .spyOn(appContext.mainProcessClient, 'subscribeToAgentUpdate')
    .mockImplementation((rootClusterUri, listener) => {
      eventEmitter.on('', listener);
      return { cleanup: () => eventEmitter.off('', listener) };
    });

  appContext.workspacesService.setConnectMyComputerAutoStart(
    rootCluster.uri,
    true
  );

  const { result } = renderUseConnectMyComputerContextHook(
    appContext,
    rootCluster
  );

  await waitFor(
    () =>
      result.current.currentAction.kind === 'observe-process' &&
      result.current.currentAction.agentProcessState.status === 'running'
  );

  expect(
    appContext.connectMyComputerService.downloadAgent
  ).toHaveBeenCalledTimes(1);
  expect(appContext.connectMyComputerService.runAgent).toHaveBeenCalledTimes(1);
});

describe('canUse', () => {
  const cases = [
    {
      name: 'should be true when the user has permissions',
      hasPermissions: true,
      isAgentConfigured: false,
      expected: true,
    },
    {
      name: 'should be true when the user does not have permissions, but the agent has been configured',
      hasPermissions: false,
      isAgentConfigured: true,
      expected: true,
    },
    {
      name: 'should be false when the user does not have permissions and the agent has not been configured',
      hasPermissions: false,
      isAgentConfigured: false,
      expected: false,
    },
  ];

  test.each(cases)(
    '$name',
    async ({ hasPermissions, isAgentConfigured, expected }) => {
      const { appContext, rootCluster } = getMocks();
      // update Connect My Computer permissions
      appContext.clustersService.setState(draftState => {
        draftState.clusters.get(
          rootCluster.uri
        ).loggedInUser.acl.tokens.create = hasPermissions;
      });
      const isAgentConfigFileCreated = Promise.resolve(isAgentConfigured);
      jest
        .spyOn(appContext.connectMyComputerService, 'isAgentConfigFileCreated')
        .mockReturnValue(isAgentConfigFileCreated);

      const { result } = renderHook(() => useConnectMyComputerContext(), {
        wrapper: ({ children }) => (
          <MockAppContextProvider appContext={appContext}>
            <WorkspaceContextProvider value={null}>
              <resourcesContext.ResourcesContextProvider>
                <ConnectMyComputerContextProvider
                  rootClusterUri={rootCluster.uri}
                >
                  {children}
                </ConnectMyComputerContextProvider>
              </resourcesContext.ResourcesContextProvider>
            </WorkspaceContextProvider>
          </MockAppContextProvider>
        ),
      });

      await act(() => isAgentConfigFileCreated);

      expect(result.current.canUse).toBe(expected);
    }
  );
});

test('removing the agent shows a notification', async () => {
  const { appContext, rootCluster } = getMocks();
  jest
    .spyOn(appContext.connectMyComputerService, 'getConnectMyComputerNodeName')
    .mockResolvedValue(makeServer().name);

  const mockResourcesContext = {
    requestResourcesRefresh: jest.fn(),
    onResourcesRefreshRequest: jest.fn(),
  };
  jest
    .spyOn(resourcesContext, 'useResourcesContext')
    .mockImplementation(() => mockResourcesContext);

  const { result } = renderUseConnectMyComputerContextHook(
    appContext,
    rootCluster
  );

  await act(() =>
    expect(result.current.removeAgent()).resolves.toEqual([
      undefined,
      null /* no error */,
    ])
  );

  expect(appContext.notificationsService.getNotifications()).toEqual([
    {
      id: expect.any(String),
      severity: 'info',
      content: 'The agent has been removed.',
    },
  ]);
  expect(mockResourcesContext.requestResourcesRefresh).toHaveBeenCalledTimes(1);
});

test('when the user does not have permissions to remove node a custom notification is shown', async () => {
  const { appContext, rootCluster } = getMocks();
  jest
    .spyOn(appContext.connectMyComputerService, 'removeConnectMyComputerNode')
    .mockRejectedValue(new Error('access denied'));
  jest
    .spyOn(appContext.connectMyComputerService, 'getConnectMyComputerNodeName')
    .mockResolvedValue(makeServer().name);
  const mockResourcesContext = {
    requestResourcesRefresh: jest.fn(),
    onResourcesRefreshRequest: jest.fn(),
  };
  jest
    .spyOn(resourcesContext, 'useResourcesContext')
    .mockImplementation(() => mockResourcesContext);

  const { result } = renderUseConnectMyComputerContextHook(
    appContext,
    rootCluster
  );

  await act(() =>
    expect(result.current.removeAgent()).resolves.toEqual([
      undefined,
      null /* no error */,
    ])
  );

  expect(appContext.notificationsService.getNotifications()).toEqual([
    {
      id: expect.any(String),
      severity: 'info',
      content: {
        title: 'The agent has been removed.',
        description:
          'The corresponding server may still be visible in the cluster for a few more minutes until it gets purged from the cache.',
      },
    },
  ]);
  expect(mockResourcesContext.requestResourcesRefresh).not.toHaveBeenCalled();
});
