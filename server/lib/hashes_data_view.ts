import { HASHES_INDEX_NAME } from './hashes_index';

export const HASHES_DATA_VIEW_ID = 'xdr-defense-hashes-data-view';

export async function ensureHashesDataView(repo: any): Promise<void> {
  const result = await repo.bulkCreate(
    [
      {
        type: 'index-pattern',
        id: HASHES_DATA_VIEW_ID,
        attributes: {
          title: HASHES_INDEX_NAME,
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
      `Failed to install hashes data view (${savedObject.error.statusCode}): ${savedObject.error.message}`
    );
  }
}
