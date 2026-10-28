import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import sync_extensions as sync

OLD = 'a' * 32
NEW = 'b' * 32
NOW = '2026-10-29T09:00:00+09:00'

def row(eid, name='Sample', category='malware'):
    return dict(zip(sync.TARGET_COLUMNS, [name, eid, category, 'malicious', '', '']))


class ObservationTests(unittest.TestCase):
    def test_store_page_requires_matching_id_and_install_text(self):
        page = f"<link href='https://chromewebstore.google.com/detail/sample/{OLD}' rel='canonical'><button>Add to Chrome</button>"
        self.assertTrue(sync.store_page_active(page, OLD))
        with self.assertRaises(ValueError):
            sync.store_page_active(page, NEW)
        with self.assertRaises(ValueError):
            sync.store_page_active(page.replace('<button>Add to Chrome</button>', ''), OLD)

    def test_store_script_install_text_is_not_evidence(self):
        with self.assertRaises(ValueError):
            sync.store_page_active(f'<link rel="canonical" href="https://chromewebstore.google.com/detail/{OLD}"><script>"Add to Chrome"</script>', OLD)

    def test_store_explicit_unavailable(self):
        self.assertFalse(sync.store_page_active('<p>This item is not available</p>', OLD))

    def test_initial_source_includes_inactive_and_excluded_ids(self):
        state, initial = sync.update_observations([row(OLD), row(NEW, category='VPN')], None, set(), NOW)
        self.assertTrue(initial)
        self.assertEqual(set(state['ids']), {OLD, NEW})
        self.assertEqual(sync.select_new_items([row(OLD), row(NEW)], state, NOW), [])

    def test_old_reappearance_never_alerts(self):
        state, _ = sync.update_observations([row(OLD)], None, set(), NOW)
        state, _ = sync.update_observations([], state, set(), NOW)
        state, _ = sync.update_observations([row(OLD)], state, set(), NOW)
        self.assertEqual(sync.select_new_items([row(OLD)], state, NOW), [])

    def test_new_id_can_qualify_later_and_only_alerts_once(self):
        state, _ = sync.update_observations([row(OLD)], None, set(), NOW)
        state, _ = sync.update_observations([row(OLD), row(NEW)], state, set(), NOW)
        self.assertEqual(sync.select_new_items([], state, NOW), [])
        self.assertEqual(sync.select_new_items([row(NEW)], state, NOW), [row(NEW)])
        state = json.loads(json.dumps(state))
        self.assertEqual(sync.select_new_items([row(NEW)], state, NOW), [])

    def test_existing_csv_id_not_realerted(self):
        state, _ = sync.update_observations([row(OLD)], None, set(), NOW)
        state, _ = sync.update_observations([row(NEW)], state, {NEW}, NOW)
        self.assertEqual(sync.select_new_items([row(NEW)], state, NOW), [])

    def test_main_failure_preserves_csv_and_state(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            output, state_path = root / 'list.csv', root / 'state.json'
            output.write_bytes(b'previous CSV')
            state, _ = sync.update_observations([row(OLD)], None, set(), NOW)
            state_path.write_text(json.dumps(state), encoding='utf-8')
            before = state_path.read_bytes()
            with patch.object(sync, 'OUTPUT_CSV_PATH', str(output)), patch.object(sync, 'STATE_PATH', str(state_path)), patch.object(sync, 'load_exclude_ids', return_value=set()), patch.object(sync, 'load_existing_ids', return_value={OLD}), patch.object(sync, 'fetch_source_rows', return_value=[row(OLD)]), patch.object(sync, 'check_webstore_active', side_effect=RuntimeError('timeout')):
                with self.assertRaises(RuntimeError):
                    sync.main()
            self.assertEqual(output.read_bytes(), b'previous CSV')
            self.assertEqual(state_path.read_bytes(), before)

    def test_main_filters_and_persists_history(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            paths = {'OUTPUT_CSV_PATH': str(root / 'list.csv'), 'STATE_PATH': str(root / 'state.json'), 'REPORT_HTML_PATH': str(root / 'report.html')}
            source = [row(OLD), row('bad@example'), row(NEW, 'N/A'), row('c'*32, category='VPN'), row('d'*32, category='PROXY'), row('e'*32, category='PROXY/VPN')]
            with patch.multiple(sync, **paths), patch.object(sync, 'load_exclude_ids', return_value=set()), patch.object(sync, 'fetch_source_rows', return_value=source), patch.object(sync, 'check_webstore_active', side_effect=lambda r: r) as check, patch.dict(os.environ, {'GITHUB_OUTPUT': str(root / 'outputs')}):
                sync.main()
                self.assertEqual(check.call_count, 1)
                self.assertIn('has_new=false', (root / 'outputs').read_text())
                self.assertEqual(len(json.loads((root / 'state.json').read_text())['ids']), 6)
                source.append(row(NEW))
                sync.main()  # 기준선에서 이미 관측한 ID는 다시 알리지 않는다.
                self.assertFalse((root / 'report.html').exists())
                source.append(row('f'*32))
                sync.main()
                self.assertTrue((root / 'report.html').exists())
                self.assertIn('new_count=1', (root / 'outputs').read_text())
                sync.main()  # 메일 미발송 상태는 다음 실행에서도 대기열을 유지한다.
                self.assertTrue((root / 'report.html').exists())
                state = json.loads((root / 'state.json').read_text())
                self.assertEqual(set(state['pending_notifications']), {'f'*32})
                sync.acknowledge_notifications()
                sync.main()
                self.assertFalse((root / 'report.html').exists())
                state = json.loads((root / 'state.json').read_text())
                self.assertEqual(state['pending_notifications'], {})
                self.assertIn('emailed_at', state['ids']['f'*32])


if __name__ == '__main__':
    unittest.main()
