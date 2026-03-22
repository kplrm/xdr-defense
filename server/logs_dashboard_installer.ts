import { ISavedObjectsRepository, Logger } from '../../../src/core/server';

const INDEX_PATTERN_ID = 'xdr-defense-agent-logs';
const DASHBOARD_ID = 'xdr-defense-detection-prevention-logs-dashboard';

const VIS_TOTAL_LOGS = 'xdr-defense-vis-total-logs';
const VIS_LOGS_TIMELINE = 'xdr-defense-vis-logs-over-time';
const VIS_LOG_LEVELS = 'xdr-defense-vis-log-levels';
const VIS_TOP_AGENTS = 'xdr-defense-vis-top-agents';
const VIS_TOP_ACTIONS = 'xdr-defense-vis-top-actions';
const VIS_RECENT_MESSAGES = 'xdr-defense-vis-recent-messages';

const ss = (query = '') =>
  JSON.stringify({
    index: INDEX_PATTERN_ID,
    query: { query, language: 'kuery' },
    filter: [],
  });

function vis(id: string, title: string, description: string, visState: string, query = '') {
  return {
    type: 'visualization',
    id,
    attributes: {
      title,
      visState,
      uiStateJSON: '{}',
      description,
      version: 1,
      kibanaSavedObjectMeta: { searchSourceJSON: ss(query) },
    },
    references: [],
  };
}

function dashboard(
  id: string,
  title: string,
  description: string,
  panels: Array<{ x: number; y: number; w: number; h: number; ref: string }>,
  refs: Array<{ name: string; id: string }>
) {
  let idx = 1;
  const panelsJSON = panels.map((panel) => {
    const panelIndex = String(idx++);
    return {
      embeddableConfig: {},
      gridData: { x: panel.x, y: panel.y, w: panel.w, h: panel.h, i: panelIndex },
      panelIndex,
      version: '2.19.0',
      panelRefName: panel.ref,
    };
  });

  return {
    type: 'dashboard',
    id,
    attributes: {
      title,
      hits: 0,
      description,
      panelsJSON: JSON.stringify(panelsJSON),
      optionsJSON: JSON.stringify({ hidePanelTitles: false, useMargins: true }),
      version: 1,
      timeRestore: true,
      timeFrom: 'now-24h',
      timeTo: 'now',
      refreshInterval: { pause: false, value: 30000 },
      kibanaSavedObjectMeta: {
        searchSourceJSON: JSON.stringify({
          query: { language: 'kuery', query: '' },
          filter: [],
        }),
      },
    },
    references: refs.map((ref) => ({ name: ref.name, type: 'visualization', id: ref.id })),
  };
}

const metricCountVis = (title: string) =>
  JSON.stringify({
    title,
    type: 'metric',
    params: {
      addTooltip: true,
      addLegend: false,
      type: 'metric',
      metric: {
        percentageMode: false,
        useRanges: false,
        colorSchema: 'Green to Red',
        metricColorMode: 'None',
        colorsRange: [{ from: 0, to: 10000 }],
        labels: { show: true },
        style: { bgFill: '#000', bgColor: false, labelColor: false, subText: '', fontSize: 60 },
      },
    },
    aggs: [{ id: '1', enabled: true, type: 'count', schema: 'metric', params: { customLabel: 'Logs' } }],
  });

const areaCountVis = (title: string, splitField?: string) => {
  const aggs: Array<Record<string, unknown>> = [
    { id: '1', enabled: true, type: 'count', schema: 'metric', params: { customLabel: 'Logs' } },
    {
      id: '2',
      enabled: true,
      type: 'date_histogram',
      schema: 'segment',
      params: { field: '@timestamp', interval: 'auto', min_doc_count: 1, extended_bounds: {} },
    },
  ];

  if (splitField) {
    aggs.push({
      id: '3',
      enabled: true,
      type: 'terms',
      schema: 'group',
      params: {
        field: splitField,
        size: 8,
        order: 'desc',
        orderBy: '1',
        otherBucket: true,
        otherBucketLabel: 'Other',
        missingBucket: true,
        missingBucketLabel: 'Unknown',
      },
    });
  }

  return JSON.stringify({
    title,
    type: 'area',
    params: {
      type: 'area',
      grid: { categoryLines: false, style: { color: '#eee' } },
      categoryAxes: [
        {
          id: 'CategoryAxis-1',
          type: 'category',
          position: 'bottom',
          show: true,
          style: {},
          scale: { type: 'linear' },
          labels: { show: true, truncate: 100, filter: true },
          title: {},
        },
      ],
      valueAxes: [
        {
          id: 'ValueAxis-1',
          name: 'LeftAxis-1',
          type: 'value',
          position: 'left',
          show: true,
          style: {},
          scale: { type: 'linear', mode: 'normal' },
          labels: { show: true, rotate: 0, filter: false, truncate: 100 },
          title: { text: 'Logs' },
        },
      ],
      seriesParams: [
        {
          show: true,
          type: 'area',
          mode: 'stacked',
          data: { label: 'Logs', id: '1' },
          drawLinesBetweenPoints: true,
          showCircles: true,
          interpolate: 'linear',
          lineWidth: 2,
          valueAxis: 'ValueAxis-1',
        },
      ],
      addTooltip: true,
      addLegend: true,
      legendPosition: 'top',
      times: [],
      addTimeMarker: false,
    },
    aggs,
  });
};

const pieVis = (title: string, field: string, label: string) =>
  JSON.stringify({
    title,
    type: 'pie',
    params: {
      type: 'pie',
      addTooltip: true,
      addLegend: true,
      legendPosition: 'right',
      isDonut: true,
      labels: { show: true, values: true, last_level: true, truncate: 100 },
    },
    aggs: [
      { id: '1', enabled: true, type: 'count', schema: 'metric', params: {} },
      {
        id: '2',
        enabled: true,
        type: 'terms',
        schema: 'segment',
        params: {
          field,
          size: 10,
          order: 'desc',
          orderBy: '1',
          otherBucket: true,
          otherBucketLabel: 'Other',
          missingBucket: true,
          missingBucketLabel: 'Unknown',
          customLabel: label,
        },
      },
    ],
  });

const scriptedPieVis = (title: string, source: string, label: string) =>
  JSON.stringify({
    title,
    type: 'pie',
    params: {
      type: 'pie',
      addTooltip: true,
      addLegend: true,
      legendPosition: 'right',
      isDonut: true,
      labels: { show: true, values: true, last_level: true, truncate: 100 },
    },
    aggs: [
      { id: '1', enabled: true, type: 'count', schema: 'metric', params: {} },
      {
        id: '2',
        enabled: true,
        type: 'terms',
        schema: 'segment',
        params: {
          size: 10,
          order: 'desc',
          orderBy: '1',
          otherBucket: true,
          otherBucketLabel: 'Other',
          missingBucket: true,
          missingBucketLabel: 'Unknown',
          customLabel: label,
          script: {
            lang: 'painless',
            source,
          },
        },
      },
    ],
  });

const topNBarVis = (title: string, field: string, xLabel: string) =>
  JSON.stringify({
    title,
    type: 'horizontal_bar',
    params: {
      type: 'horizontal_bar',
      grid: { categoryLines: false, style: { color: '#eee' } },
      categoryAxes: [
        {
          id: 'CategoryAxis-1',
          type: 'category',
          position: 'left',
          show: true,
          style: {},
          scale: { type: 'linear' },
          labels: { show: true, truncate: 200, filter: true },
          title: {},
        },
      ],
      valueAxes: [
        {
          id: 'ValueAxis-1',
          name: 'BottomAxis-1',
          type: 'value',
          position: 'bottom',
          show: true,
          style: {},
          scale: { type: 'linear', mode: 'normal' },
          labels: { show: true, rotate: 0, filter: false, truncate: 100 },
          title: { text: xLabel },
        },
      ],
      seriesParams: [{ show: true, type: 'histogram', mode: 'normal', data: { label: 'Logs', id: '1' }, valueAxis: 'ValueAxis-1' }],
      addTooltip: true,
      addLegend: false,
      legendPosition: 'right',
      times: [],
      addTimeMarker: false,
    },
    aggs: [
      { id: '1', enabled: true, type: 'count', schema: 'metric', params: { customLabel: 'Logs' } },
      {
        id: '2',
        enabled: true,
        type: 'terms',
        schema: 'segment',
        params: {
          field,
          size: 10,
          order: 'desc',
          orderBy: '1',
          otherBucket: true,
          otherBucketLabel: 'Other',
          missingBucket: true,
          missingBucketLabel: 'Unknown',
        },
      },
    ],
  });

const dataTableVis = (title: string) =>
  JSON.stringify({
    title,
    type: 'table',
    params: {
      perPage: 10,
      showPartialRows: false,
      showMetricsAtAllLevels: false,
      sort: { columnIndex: 0, direction: 'desc' },
      showTotal: false,
      totalFunc: 'sum',
      percentageCol: '',
    },
    aggs: [
      { id: '1', enabled: true, type: 'count', schema: 'metric', params: { customLabel: 'Logs' } },
      {
        id: '2',
        enabled: true,
        type: 'terms',
        schema: 'bucket',
        params: {
          field: 'message',
          size: 10,
          order: 'desc',
          orderBy: '1',
          otherBucket: false,
          missingBucket: false,
          customLabel: 'Message',
        },
      },
      {
        id: '3',
        enabled: true,
        type: 'terms',
        schema: 'bucket',
        params: {
          field: 'agent.id',
          size: 3,
          order: 'desc',
          orderBy: '1',
          otherBucket: false,
          missingBucket: true,
          missingBucketLabel: 'unknown-agent',
          customLabel: 'Agent',
        },
      },
    ],
  });

function buildSavedObjects() {
  const indexPattern = {
    type: 'index-pattern',
    id: INDEX_PATTERN_ID,
    attributes: {
      title: 'xdr-agent-logs-*',
      timeFieldName: '@timestamp',
      fields: '[]',
    },
    references: [],
  };

  const logsQuery = 'event.module: (xdr-agent or xdr-defense)';

  const totalLogs = vis(
    VIS_TOTAL_LOGS,
    '[XDR Defense] Total Logs',
    'Total count of detection and prevention related logs',
    metricCountVis('[XDR Defense] Total Logs'),
    logsQuery
  );

  const logsTimeline = vis(
    VIS_LOGS_TIMELINE,
    '[XDR Defense] Logs Over Time',
    'Trend of logs over time split by log level',
    areaCountVis('[XDR Defense] Logs Over Time', 'log.level'),
    logsQuery
  );

  const logLevels = vis(
    VIS_LOG_LEVELS,
    '[XDR Defense] Log Level Distribution',
    'Distribution of log levels from normalized field',
    pieVis('[XDR Defense] Log Level Distribution', 'log.level', 'Log level'),
    logsQuery
  );

  const topAgents = vis(
    VIS_TOP_AGENTS,
    '[XDR Defense] Top Agents',
    'Agents producing the most detection/prevention logs',
    topNBarVis('[XDR Defense] Top Agents', 'agent.id', 'Logs'),
    logsQuery
  );

  const topActions = vis(
    VIS_TOP_ACTIONS,
    '[XDR Defense] Top Detection/Prevention Actions',
    'Top event.action with fallback to event.category',
    scriptedPieVis(
      '[XDR Defense] Top Detection/Prevention Actions',
      "if (doc.containsKey('event.action.keyword') && !doc['event.action.keyword'].empty) { return doc['event.action.keyword'].value; } if (doc.containsKey('event.category.keyword') && !doc['event.category.keyword'].empty) { return doc['event.category.keyword'].value; } return 'unknown';",
      'Action/category'
    ),
    logsQuery
  );

  const recentMessages = vis(
    VIS_RECENT_MESSAGES,
    '[XDR Defense] Recent Messages',
    'Table of most frequent recent messages grouped by agent',
    dataTableVis('[XDR Defense] Recent Messages'),
    logsQuery
  );

  const dashboardObject = dashboard(
    DASHBOARD_ID,
    'XDR Defense - Detection and Prevention Logs',
    'Out-of-the-box dashboard for xdr-agent detection and prevention logs.',
    [
      { x: 0, y: 0, w: 12, h: 8, ref: 'panel_0' },
      { x: 12, y: 0, w: 36, h: 16, ref: 'panel_1' },
      { x: 0, y: 8, w: 24, h: 16, ref: 'panel_2' },
      { x: 24, y: 16, w: 24, h: 16, ref: 'panel_3' },
      { x: 0, y: 24, w: 24, h: 16, ref: 'panel_4' },
      { x: 0, y: 40, w: 48, h: 18, ref: 'panel_5' },
    ],
    [
      { name: 'panel_0', id: VIS_TOTAL_LOGS },
      { name: 'panel_1', id: VIS_LOGS_TIMELINE },
      { name: 'panel_2', id: VIS_LOG_LEVELS },
      { name: 'panel_3', id: VIS_TOP_AGENTS },
      { name: 'panel_4', id: VIS_TOP_ACTIONS },
      { name: 'panel_5', id: VIS_RECENT_MESSAGES },
    ]
  );

  return {
    indexPatterns: [indexPattern],
    dashboardObjects: [
      totalLogs,
      logsTimeline,
      logLevels,
      topAgents,
      topActions,
      recentMessages,
      dashboardObject,
    ],
  };
}

export async function installDetectionPreventionLogsDashboard(
  repo: ISavedObjectsRepository,
  logger: Logger
): Promise<void> {
  const { indexPatterns, dashboardObjects } = buildSavedObjects();

  try {
    const indexPatternResult = await repo.bulkCreate(indexPatterns as any[], { overwrite: false });
    const indexPatternErrors = indexPatternResult.saved_objects.filter(
      (obj: any) => obj.error && obj.error.statusCode !== 409
    );
    if (indexPatternErrors.length > 0) {
      logger.warn(
        `xdr_defense: logs index-pattern install error: ${indexPatternErrors
          .map((obj: any) => `${obj.type}/${obj.id}: ${obj.error.message}`)
          .join('; ')}`
      );
    }

    const dashboardResult = await repo.bulkCreate(dashboardObjects as any[], { overwrite: true });
    const dashboardErrors = dashboardResult.saved_objects.filter((obj: any) => obj.error);
    const createdCount = dashboardResult.saved_objects.filter((obj: any) => !obj.error).length;

    if (dashboardErrors.length > 0) {
      logger.warn(
        `xdr_defense: logs dashboard install had ${dashboardErrors.length} error(s): ${dashboardErrors
          .map((obj: any) => `${obj.type}/${obj.id}: ${obj.error?.message}`)
          .join('; ')}`
      );
    }

    logger.info(`xdr_defense: installed detection/prevention logs dashboard (${createdCount} objects written)`);
  } catch (err) {
    logger.error(`xdr_defense: failed to install detection/prevention logs dashboard: ${err}`);
  }
}
