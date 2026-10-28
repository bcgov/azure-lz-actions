const test = require('node:test');
const assert = require('node:assert/strict');
const { cleanup } = require('../cleanup');
const {
  buildCreateRuleArgs,
  isNotFoundError,
  isValidAddressPrefix,
  normalizeDirection,
  operationRuleName,
  ownershipDescription,
  selectPriority,
  validateInputs
} = require('../validation');
const { runAzureCli, saveCleanupState } = require('../index');

const validInputs = {
  subscriptionId: '00000000-0000-0000-0000-000000000001',
  resourceGroup: 'private-network-rg',
  nsgName: 'runner-nsg',
  ruleName: 'github-runner',
  sourceIp: '10.20.1.15',
  sourcePrefixesRaw: '',
  allowAnySource: 'false',
  destinationPorts: '443,8443',
  protocol: 'Tcp',
  direction: 'Inbound',
  destinationPrefixesRaw: '10.30.0.0/16',
  priority: '3000',
  cleanupEnabled: 'true'
};

function fakeCore(initialState = {}) {
  const state = { failed: [], warnings: [], infos: [], groupEnds: 0 };
  const savedState = new Map(Object.entries(initialState));
  const summary = {
    addHeading() { return this; },
    addTable(rows) { this.tables.push(rows); return this; },
    tables: [],
    write: async () => {}
  };
  return {
    state,
    summary,
    startGroup() {},
    endGroup() { state.groupEnds += 1; },
    warning(message) { state.warnings.push(message); },
    error(message) { state.warnings.push(message); },
    info(message) { state.infos.push(message); },
    debug() {},
    setFailed(message) { state.failed.push(message); },
    saveState(name, value) { savedState.set(name, value); },
    getState(name) { return savedState.get(name) || ''; }
  };
}

test('validates source IPs, CIDRs, and port ranges', () => {
  assert.deepEqual(validateInputs(validInputs), []);
  assert.equal(isValidAddressPrefix('10.20.1.15/32'), true);
  assert.equal(isValidAddressPrefix('300.20.1.15/32'), false);
  assert.equal(isValidAddressPrefix('10.20.1.0/33'), false);
});

test('rejects invalid cleanup-enabled values before boolean conversion', () => {
  const errors = validateInputs({ ...validInputs, cleanupEnabled: 'yes' });
  assert.ok(errors.some(error => error.includes("cleanup-enabled must be 'true' or 'false'")));
});

test('normalizes direction case and selects a free NSG priority', () => {
  assert.equal(normalizeDirection('inbound'), 'Inbound');
  assert.deepEqual(validateInputs({ ...validInputs, direction: 'inbound' }), []);
  assert.equal(selectPriority([{ priority: 3000, direction: 'Inbound' }], 'Inbound', ''), '3001');
  assert.equal(selectPriority([{ priority: 3000, direction: 'Outbound' }], 'Inbound', ''), '3000');
  assert.throws(() => selectPriority([{ priority: 3000, direction: 'Inbound' }], 'Inbound', '3000'), /already in use/);
});

test('classifies Azure not-found errors without matching echoed command text', () => {
  assert.equal(isNotFoundError({ message: 'az ... target-notfound-nsg ... authorization failed' }), false);
  assert.equal(isNotFoundError({ stderr: 'ResourceNotFound: the requested resource was not found' }), true);
});

test('rejects unsafe priority text, invalid ranges, and unrestricted sources by default', () => {
  const errors = validateInputs({
    ...validInputs,
    priority: '3000; echo unsafe',
    destinationPorts: '443-80',
    sourceIp: '',
    sourcePrefixesRaw: '*'
  });
  assert.ok(errors.some(error => error.includes('priority')));
  assert.ok(errors.some(error => error.includes('destination ports')));
  assert.ok(errors.some(error => error.includes('allow-any-source')));
});

test('requires explicit opt-in for wildcard source prefixes', () => {
  assert.deepEqual(validateInputs({ ...validInputs, sourceIp: '', sourcePrefixesRaw: '*', allowAnySource: 'true' }), []);
});

test('adds a unique bounded rule name and operation ownership marker', () => {
  const operationId = '12345678-1234-4234-9234-123456789abc';
  const name = operationRuleName('a'.repeat(80), operationId);
  assert.equal(name.length, 80);
  assert.match(name, /-1234567812344234$/);
  assert.equal(ownershipDescription(operationId), `Managed by nsg-jit-rule; operation=${operationId}`);
});

test('builds Azure CLI arguments without shell interpolation', () => {
  const args = buildCreateRuleArgs({
    ...validInputs,
    ruleName: 'runner-123',
    sourcePrefixes: ['10.20.1.15/32'],
    destinationPrefixes: ['10.30.0.0/16'],
    ownershipDescription: 'Managed by nsg-jit-rule; operation=test'
  });
  assert.ok(args.includes('3000'));
  assert.ok(args.includes('10.20.1.15/32'));
  const portArgumentIndex = args.indexOf('--destination-port-ranges') + 1;
  assert.deepEqual(args.slice(portArgumentIndex, portArgumentIndex + 2), ['443', '8443']);

  let invocation;
  runAzureCli(['network', 'nsg', 'show'], validInputs.subscriptionId, (file, commandArgs, options) => {
    invocation = { file, commandArgs, options };
    return '';
  });
  assert.equal(invocation.file, 'az');
  assert.deepEqual(invocation.commandArgs.slice(-2), ['--subscription', validInputs.subscriptionId]);
  assert.equal('shell' in invocation.options, false);
});

test('cleanup refuses to delete a same-name rule without this operation marker', async () => {
  const actionCore = fakeCore({
    'rule-name': 'runner-123',
    'nsg-name': 'runner-nsg',
    'resource-group': 'private-network-rg',
    'subscription-id': validInputs.subscriptionId,
    'ownership-description': 'expected marker',
    'operation-id': 'test-operation'
  });
  const commands = [];

  await cleanup({
    actionCore,
    sleep: async () => {},
    runAz: args => {
      commands.push(args);
      return JSON.stringify({ description: 'another operation' });
    }
  });

  assert.equal(commands.some(args => args[3] === 'delete'), false);
  assert.equal(actionCore.state.failed.length, 1);
});

test('cleanup removes an owned rule and reports success', async () => {
  const actionCore = fakeCore({
    'rule-name': 'runner-123',
    'nsg-name': 'runner-nsg',
    'resource-group': 'private-network-rg',
    'subscription-id': validInputs.subscriptionId,
    'ownership-description': 'expected marker',
    'operation-id': 'test-operation'
  });
  let deleted = false;
  const runAz = args => {
    if (args[3] === 'delete') {
      deleted = true;
      return '';
    }
    if (deleted) {
      const error = new Error('ResourceNotFound');
      error.code = 'ResourceNotFound';
      throw error;
    }
    return JSON.stringify({ description: 'expected marker' });
  };

  await cleanup({ actionCore, runAz, sleep: async () => {} });

  assert.equal(deleted, true);
  assert.deepEqual(actionCore.state.failed, []);
  assert.equal(actionCore.state.groupEnds, 1);
});

test('cleanup reports an absent rule instead of claiming it removed one', async () => {
  const actionCore = fakeCore({
    'rule-name': 'runner-123',
    'nsg-name': 'runner-nsg',
    'resource-group': 'private-network-rg',
    'subscription-id': validInputs.subscriptionId,
    'ownership-description': 'expected marker',
    'operation-id': 'test-operation'
  });

  await cleanup({
    actionCore,
    runAz: () => {
      const error = new Error('resource was not found');
      error.stderr = '(ResourceNotFound)';
      throw error;
    },
    sleep: async () => {}
  });

  assert.deepEqual(actionCore.state.failed, []);
  assert.ok(actionCore.summary.tables.flat().some(row => Array.isArray(row) && row[0] === 'Status' && row[1] === 'Already absent'));
});

test('cleanup failure marks the action failed', async () => {
  const actionCore = fakeCore({
    'rule-name': 'runner-123',
    'nsg-name': 'runner-nsg',
    'resource-group': 'private-network-rg',
    'subscription-id': validInputs.subscriptionId,
    'ownership-description': 'expected marker',
    'operation-id': 'test-operation'
  });
  let failDelete = false;
  const runAz = args => {
    if (args[3] === 'delete') {
      failDelete = true;
      throw new Error('Azure CLI delete failed');
    }
    if (failDelete) return JSON.stringify({ description: 'expected marker' });
    return JSON.stringify({ description: 'expected marker' });
  };

  await cleanup({ actionCore, runAz, sleep: async () => {} });

  assert.equal(actionCore.state.failed.length, 1);
  assert.match(actionCore.state.failed[0], /cleanup failed/i);
});

test('stores cleanup data in isolated per-action state for matrix targets', async () => {
  const operationId = '12345678-1234-4234-9234-123456789abc';
  const targets = [
    { resourceGroup: 'rg-one', nsgName: 'nsg-one', subscriptionId: '00000000-0000-0000-0000-000000000001' },
    { resourceGroup: 'rg-two', nsgName: 'nsg-two', subscriptionId: '00000000-0000-0000-0000-000000000002' }
  ];
  const invocations = [];

  for (const [index, target] of targets.entries()) {
    const actionCore = fakeCore();
    const inputs = {
      ...target,
      ruleName: `runner-${index}`,
      ownershipDescription: `Managed by nsg-jit-rule; operation=${operationId}-${index}`,
      cleanupEnabled: true
    };
    const execution = { operation_id: `${operationId}-${index}` };
    saveCleanupState(inputs, execution, actionCore);

    let deleted = false;
    const commands = [];
    await cleanup({
      actionCore,
      sleep: async () => {},
      runAz: (args, subscriptionId) => {
        commands.push({ args, subscriptionId });
        if (args[3] === 'delete') {
          deleted = true;
          return '';
        }
        if (deleted) {
          const error = new Error('ResourceNotFound');
          error.code = 'ResourceNotFound';
          throw error;
        }
        return JSON.stringify({ description: inputs.ownershipDescription });
      }
    });
    invocations.push({ target, commands, deleted, failed: actionCore.state.failed });
  }

  assert.deepEqual(invocations.map(item => item.deleted), [true, true]);
  assert.deepEqual(invocations.map(item => item.failed), [[], []]);
  for (const [index, invocation] of invocations.entries()) {
    assert.ok(invocation.commands.every(command => command.subscriptionId === targets[index].subscriptionId));
    assert.ok(invocation.commands.every(command => command.args.includes(targets[index].resourceGroup)));
    assert.ok(invocation.commands.every(command => command.args.includes(targets[index].nsgName)));
  }
});
