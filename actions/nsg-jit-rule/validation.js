const net = require('net');

const PRIORITY_MIN = 100;
const PRIORITY_MAX = 4096;
const VALID_PROTOCOLS = ['TCP', 'UDP', '*'];
const VALID_DIRECTIONS = ['Inbound', 'Outbound'];

function toBoolean(value, defaultValue = true) {
  if (value === undefined || value === null || String(value).trim() === '') {
    return defaultValue;
  }
  return String(value).trim().toLowerCase() === 'true';
}

function normalizePrefixes(raw, defaults) {
  const parsed = String(raw || '')
    .split(',')
    .map(prefix => prefix.trim())
    .filter(Boolean);

  return parsed.length > 0 ? parsed : defaults;
}

function normalizeDirection(direction) {
  return VALID_DIRECTIONS.find(value => value.toLowerCase() === String(direction).toLowerCase()) || direction;
}

function selectPriority(existingRules, direction, requestedPriority, priorityMin = PRIORITY_MIN, priorityMax = PRIORITY_MAX) {
  const minimum = Number(priorityMin);
  const maximum = Number(priorityMax);
  const usedPriorities = new Set((existingRules || [])
    .filter(rule => String(rule.direction).toLowerCase() === String(direction).toLowerCase())
    .map(rule => Number(rule.priority)));

  if (String(requestedPriority || '').trim() !== '') {
    const priority = Number(requestedPriority);
    if (priority < minimum || priority > maximum) {
      throw new Error(`Priority ${priority} is outside the configured range ${minimum}-${maximum}`);
    }
    if (usedPriorities.has(priority)) {
      throw new Error(`Priority ${priority} is already in use for ${direction} rules on this NSG`);
    }
    return String(priority);
  }

  const startingPriority = Math.min(Math.max(3000, minimum), maximum);
  for (let priority = startingPriority; priority <= maximum; priority++) {
    if (!usedPriorities.has(priority)) return String(priority);
  }
  for (let priority = startingPriority - 1; priority >= minimum; priority--) {
    if (!usedPriorities.has(priority)) return String(priority);
  }

  throw new Error(`No available priority remains for ${direction} rules in the configured range ${minimum}-${maximum}`);
}

function isValidAddressPrefix(prefix) {
  if (prefix === '*') return true;

  const parts = prefix.split('/');
  if (parts.length > 2 || !net.isIPv4(parts[0])) return false;
  if (parts.length === 1) return true;

  return /^\d+$/.test(parts[1]) && Number(parts[1]) <= 32;
}

function isValidPortRange(value) {
  if (value === '*') return true;

  return value.split(',').every(part => {
    const match = /^(\d+)(?:-(\d+))?$/.exec(part.trim());
    if (!match) return false;

    const start = Number(match[1]);
    const end = match[2] === undefined ? start : Number(match[2]);
    return start >= 1 && end <= 65535 && start <= end;
  });
}

function validateInputs(inputs) {
  const errors = [];

  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(inputs.subscriptionId)) {
    errors.push('Invalid subscription ID format (must be UUID)');
  }
  if (!/^[a-zA-Z0-9._()-]{1,90}$/.test(inputs.resourceGroup)) {
    errors.push('Invalid resource group name (1-90 supported characters)');
  }
  if (!/^[a-zA-Z0-9._-]{1,80}$/.test(inputs.nsgName)) {
    errors.push('Invalid NSG name (1-80 letters, numbers, dots, underscores, or hyphens)');
  }
  if (!/^[a-zA-Z0-9._-]{1,80}$/.test(inputs.ruleName)) {
    errors.push('Invalid rule name (1-80 letters, numbers, dots, underscores, or hyphens)');
  }
  if (inputs.sourceIp && !net.isIPv4(inputs.sourceIp)) {
    errors.push(`Invalid source IP: ${inputs.sourceIp}. Must be a valid IPv4 address`);
  }
  if (!VALID_PROTOCOLS.includes(inputs.protocol.toUpperCase())) {
    errors.push(`Invalid protocol: ${inputs.protocol}. Must be one of: ${VALID_PROTOCOLS.join(', ')}`);
  }
  if (!VALID_DIRECTIONS.some(direction => direction.toLowerCase() === String(inputs.direction).toLowerCase())) {
    errors.push("Invalid direction. Must be 'Inbound' or 'Outbound'");
  }

  const priorityMin = String(inputs.priorityMin ?? PRIORITY_MIN).trim();
  const priorityMax = String(inputs.priorityMax ?? PRIORITY_MAX).trim();
  const validPriorityMin = /^\d+$/.test(priorityMin) && Number(priorityMin) >= PRIORITY_MIN && Number(priorityMin) <= PRIORITY_MAX;
  const validPriorityMax = /^\d+$/.test(priorityMax) && Number(priorityMax) >= PRIORITY_MIN && Number(priorityMax) <= PRIORITY_MAX;
  if (!validPriorityMin) {
    errors.push(`Invalid priority-min: ${inputs.priorityMin}. Must be an integer between ${PRIORITY_MIN}-${PRIORITY_MAX}`);
  }
  if (!validPriorityMax) {
    errors.push(`Invalid priority-max: ${inputs.priorityMax}. Must be an integer between ${PRIORITY_MIN}-${PRIORITY_MAX}`);
  }
  const minimumPriority = validPriorityMin ? Number(priorityMin) : PRIORITY_MIN;
  const maximumPriority = validPriorityMax ? Number(priorityMax) : PRIORITY_MAX;
  if (validPriorityMin && validPriorityMax && minimumPriority > maximumPriority) {
    errors.push('priority-min must not exceed priority-max');
  }

  const priority = String(inputs.priority || '').trim();
  if (priority !== '' && (!/^\d+$/.test(priority) || Number(priority) < minimumPriority || Number(priority) > maximumPriority)) {
    errors.push(`Invalid priority: ${inputs.priority}. Must be an integer between ${minimumPriority}-${maximumPriority}`);
  }

  if (!isValidPortRange(inputs.destinationPorts)) {
    errors.push('Invalid destination ports. Use ports 1-65535, ordered ranges, comma-separated values, or *');
  }

  const sourceDefaults = inputs.sourceIp ? [`${inputs.sourceIp}/32`] : [];
  const sourcePrefixes = normalizePrefixes(inputs.sourcePrefixesRaw, sourceDefaults);
  const destinationPrefixes = normalizePrefixes(inputs.destinationPrefixesRaw, ['*']);
  const allowAnySource = toBoolean(inputs.allowAnySource, false);

  if (sourcePrefixes.length === 0) {
    errors.push('Provide source-ip or at least one source-prefixes entry');
  }
  for (const prefix of sourcePrefixes) {
    if (!isValidAddressPrefix(prefix)) {
      errors.push(`Invalid source prefix: ${prefix}`);
    } else if ((prefix === '*' || (prefix.includes('/') && Number(prefix.split('/')[1]) === 0)) && !allowAnySource) {
      errors.push(`Source prefix ${prefix} requires allow-any-source: 'true'`);
    }
  }
  for (const prefix of destinationPrefixes) {
    if (!isValidAddressPrefix(prefix)) {
      errors.push(`Invalid destination prefix: ${prefix}`);
    }
  }

  for (const [name, value] of [['cleanup-enabled', inputs.cleanupEnabled], ['allow-any-source', inputs.allowAnySource]]) {
    if (value !== undefined && String(value).trim() !== '' && !['true', 'false'].includes(String(value).trim().toLowerCase())) {
      errors.push(`${name} must be 'true' or 'false'`);
    }
  }

  return errors;
}

function operationRuleName(baseName, operationId) {
  const suffix = operationId.replace(/-/g, '').slice(0, 16).toLowerCase();
  return `${baseName.slice(0, 63)}-${suffix}`;
}

function ownershipDescription(operationId) {
  return `Managed by nsg-jit-rule; operation=${operationId}`;
}

function buildCreateRuleArgs(inputs) {
  return [
    'network', 'nsg', 'rule', 'create',
    '--resource-group', inputs.resourceGroup,
    '--nsg-name', inputs.nsgName,
    '--name', inputs.ruleName,
    '--priority', String(inputs.priority),
    '--direction', inputs.direction,
    '--access', 'Allow',
    '--protocol', inputs.protocol.toUpperCase(),
    '--source-address-prefixes', ...inputs.sourcePrefixes,
    '--destination-address-prefixes', ...inputs.destinationPrefixes,
    '--destination-port-ranges', ...inputs.destinationPorts.split(',').map(port => port.trim()).filter(Boolean),
    '--description', inputs.ownershipDescription,
    '-o', 'json'
  ];
}

function isNotFoundError(error) {
  const causes = [error, error.cause].filter(Boolean);
  const codes = causes.map(cause => String(cause.code || '').toLowerCase());
  const statuses = causes.map(cause => Number(cause.status ?? cause.statusCode));
  const stderr = causes.map(cause => String(cause.stderr || '')).join('\n');
  return codes.some(code => ['resourcenotfound', 'parentresourcenotfound', 'notfound'].includes(code)) ||
    statuses.includes(404) || /\((?:ResourceNotFound|ParentResourceNotFound|NotFound)\)/i.test(stderr) ||
    /\bstatus(?: code)?\s*[:=]?\s*404\b/i.test(stderr);
}

function isPriorityConflictError(error) {
  const causes = [error, error.cause].filter(Boolean);
  const codes = causes.map(cause => String(cause.code || '').toLowerCase());
  const stderr = causes.map(cause => String(cause.stderr || '')).join('\n');
  return codes.includes('securityruleconflict') ||
    /\(SecurityRuleConflict\)|Rules cannot have the same Priority and Direction/i.test(stderr);
}

module.exports = {
  buildCreateRuleArgs,
  isNotFoundError,
  isPriorityConflictError,
  isValidAddressPrefix,
  normalizePrefixes,
  normalizeDirection,
  operationRuleName,
  ownershipDescription,
  selectPriority,
  toBoolean,
  validateInputs
};
