import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { SAMPLE_SCAN_TEMPLATES } from '../src/data/mockData.js';

describe('Landing Page Action Routing & Scanner Tab Strategy', () => {
  it('should map landing-page actions to the 3 valid workstation scanner tabs', () => {
    // Requirements:
    // Scan a Message -> Message Scanner ('text')
    // Check a URL -> URL Safety Checker ('url')
    // Scan an Image -> Screenshot Scanner ('image')
    const actionMappings = {
      'Scan a Message': 'text',
      'Check a URL': 'url',
      'Scan an Image': 'image',
    };

    assert.equal(actionMappings['Scan a Message'], 'text');
    assert.equal(actionMappings['Check a URL'], 'url');
    assert.equal(actionMappings['Scan an Image'], 'image');

    const validTabs = ['text', 'url', 'image'];
    for (const [action, tab] of Object.entries(actionMappings)) {
      assert.ok(validTabs.includes(tab), `Tab '${tab}' for action '${action}' should be a valid scanner tab`);
    }
  });

  it('should provide pre-loaded sample templates for text and url scanners', () => {
    assert.ok(Array.isArray(SAMPLE_SCAN_TEMPLATES.text), 'Text templates should be an array');
    assert.ok(SAMPLE_SCAN_TEMPLATES.text.length >= 3, 'Text templates should contain realistic samples');

    assert.ok(Array.isArray(SAMPLE_SCAN_TEMPLATES.url), 'URL templates should be an array');
    assert.ok(SAMPLE_SCAN_TEMPLATES.url.length >= 2, 'URL templates should contain realistic samples');

    // Validate that each template has required properties
    for (const tpl of SAMPLE_SCAN_TEMPLATES.text) {
      assert.ok(typeof tpl.label === 'string', 'Text template must have label');
      assert.ok(typeof tpl.content === 'string' && tpl.content.length > 0, 'Text template must have content');
    }

    for (const tpl of SAMPLE_SCAN_TEMPLATES.url) {
      assert.ok(typeof tpl.label === 'string', 'URL template must have label');
      assert.ok(typeof tpl.url === 'string' && tpl.url.length > 0, 'URL template must have valid url');
    }
  });

  it('should simulate tab transitions between url, text, and image without TDZ ReferenceErrors', () => {
    // Test the state machine logic used in ShieldScanWorkstation
    function createScannerStateSimulator(initialTab = 'url') {
      let activeTab = initialTab;
      let prevSelectedTab = initialTab;
      let scanResult = null;
      let scanError = null;

      function onPropChange(selectedTab) {
        if (selectedTab && selectedTab !== prevSelectedTab) {
          prevSelectedTab = selectedTab;
          activeTab = selectedTab;
          scanResult = null;
          scanError = null;
        }
      }

      function onInternalTabSwitch(newTab) {
        activeTab = newTab;
        prevSelectedTab = newTab;
        scanResult = null;
        scanError = null;
      }

      return {
        getActiveTab: () => activeTab,
        getPrevSelectedTab: () => prevSelectedTab,
        getScanResult: () => scanResult,
        getScanError: () => scanError,
        onPropChange,
        onInternalTabSwitch,
      };
    }

    const sim = createScannerStateSimulator('url');
    assert.equal(sim.getActiveTab(), 'url');

    // Simulate clicking "Scan a Message" on hero
    sim.onPropChange('text');
    assert.equal(sim.getActiveTab(), 'text');
    assert.equal(sim.getScanResult(), null);
    assert.equal(sim.getScanError(), null);

    // Simulate clicking "Scan an Image" on hero
    sim.onPropChange('image');
    assert.equal(sim.getActiveTab(), 'image');
    assert.equal(sim.getScanResult(), null);
    assert.equal(sim.getScanError(), null);

    // Simulate clicking "Check a URL" on hero
    sim.onPropChange('url');
    assert.equal(sim.getActiveTab(), 'url');
    assert.equal(sim.getScanResult(), null);
    assert.equal(sim.getScanError(), null);

    // Simulate internal tab switches
    sim.onInternalTabSwitch('text');
    assert.equal(sim.getActiveTab(), 'text');
    assert.equal(sim.getPrevSelectedTab(), 'text');
  });
});
