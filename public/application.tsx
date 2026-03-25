import React from 'react';
import ReactDOM from 'react-dom';
import { AppMountParameters, CoreStart } from '../../OpenSearch-Dashboards/src/core/public';
import { XdrDefenseApp } from './components/app';

export const renderApp = (
  { http, notifications }: CoreStart,
  { appBasePath, element }: AppMountParameters
) => {
  ReactDOM.render(
    <XdrDefenseApp basename={appBasePath} http={http} notifications={notifications} />,
    element
  );
  return () => ReactDOM.unmountComponentAtNode(element);
};
