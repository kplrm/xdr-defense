import { PluginInitializerContext } from '../../../src/core/server';
import { XdrDefenseServerPlugin } from './plugin';

export function plugin(initializerContext: PluginInitializerContext) {
  return new XdrDefenseServerPlugin(initializerContext);
}
