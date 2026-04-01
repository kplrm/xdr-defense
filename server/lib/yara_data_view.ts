import { YARA_INDEX_NAME } from './yara_index';

export const YARA_DATA_VIEW_ID = 'xdr-defense-yara-data-view';

export async function ensureYaraDataView(repo: any): Promise<void> {
  const result = await repo.bulkCreate(
    [
      {
        type: 'index-pattern',
        id: YARA_DATA_VIEW_ID,
        attributes: {
          title: YARA_INDEX_NAME,
          // Omit timeFieldName to keep Discover unfiltered by time.
          fields: '[]'
        },
        references: []
      }
    ],
    { overwrite: true }
  );

  const savedObject = result?.saved_objects?.[0];
  if (savedObject?.error) {
    throw new Error(
      `Failed to install yara data view (${savedObject.error.statusCode}): ${savedObject.error.message}`
    );
  }
}
