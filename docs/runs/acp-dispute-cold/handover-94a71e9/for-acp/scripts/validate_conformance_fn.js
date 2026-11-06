// 11. Validate dispute_resolution conformance cases against the schema
// Each case's input.record must be a valid DisputeRecord. A case's input.determination must be a valid
// DisputeDetermination unless the case expects the determination to be rejected (expect.det_ok === false):
// some of those cases are invalid on purpose.
function validateDisputeConformanceCases() {
  console.log('\n📝 Validating dispute_resolution conformance cases...\n');

  const version = 'unreleased';
  const schemaPath = path.join(__dirname, '..', 'spec', version, 'json-schema', 'schema.dispute_resolution.json');
  const casesPath = path.join(__dirname, '..', 'examples', version, 'dispute_resolution', 'conformance_cases.json');

  if (!fs.existsSync(schemaPath) || !fs.existsSync(casesPath)) {
    return;
  }

  try {
    const schema = JSON.parse(fs.readFileSync(schemaPath, 'utf8'));
    const doc = JSON.parse(fs.readFileSync(casesPath, 'utf8'));

    const ajv = new Ajv({ strict: false, allErrors: true, validateSchema: false });
    addFormats(ajv);
    ajv.addSchema(schema);
    const ref = name => ajv.getSchema((schema.$id || '') + '#/$defs/' + name);
    const validateRecord = ref('DisputeRecord');
    const validateDetermination = ref('DisputeDetermination');

    const seen = new Set();
    (doc.cases || []).forEach(c => {
      if (seen.has(c.id)) {
        error(`Conformance case id "${c.id}" is not unique`, { version, spec: 'dispute_resolution' });
      }
      seen.add(c.id);
      const input = c.input || {};
      if (!input.record || !validateRecord(input.record)) {
        error(`Conformance case "${c.id}": input.record does not validate against DisputeRecord`, {
          version, spec: 'dispute_resolution', example: c.id, errors: validateRecord.errors,
        });
      }
      const expectsRejection = c.expect && c.expect.det_ok === false;
      if (input.determination && !expectsRejection && !validateDetermination(input.determination)) {
        error(`Conformance case "${c.id}": input.determination does not validate against DisputeDetermination`, {
          version, spec: 'dispute_resolution', example: c.id, errors: validateDetermination.errors,
        });
      }
    });

    success(`${seen.size} conformance cases validated for ${version}/dispute_resolution`);
  } catch (err) {
    error(`Error validating conformance cases for ${version}/dispute_resolution: ${err.message}`, {
      version, spec: 'dispute_resolution',
    });
  }
}
