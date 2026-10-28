"""DETECTIVE 2.3: reproducible ICMP-history patterns with careful limits."""
import unittest
from datetime import datetime, timedelta, timezone

from bloodsky_net.incident_patterns import availability_index, recurrent_incidents, MAX_ROWS
from bloodsky_net.detective import recurrence_findings, export_report, export_html_report

T0 = datetime(2026, 10, 28, 10, 0, tzinfo=timezone.utc)
IP = '192.168.8.12'


def event(minutes=0, ip=IP, severity='error', title='Устройство не отвечает',
          detail=None, at=None):
    stamp = at if at is not None else T0 + timedelta(minutes=minutes)
    return (stamp.isoformat(), severity, title, detail if detail is not None else ip + ' camera')


class RecurrentPatternsTests(unittest.TestCase):
    def test_repeats_across_two_utc_days(self):
        rows = [event(0), event(-24*60), event(-48*60)]
        result = recurrent_incidents(rows, T0)
        self.assertEqual(len(result), 1)
        self.assertEqual((result[0].episodes, result[0].distinct_utc_days), (3,3))
        self.assertEqual(result[0].recurring_utc_hour, 10)

    def test_three_events_same_day_not_recurring(self):
        self.assertEqual(recurrent_incidents([event(-i*60) for i in range(3)],T0), ())

    def test_repeated_logging_not_three_episodes(self):
        rows = [event(-24*60), event(-24*60-3), event(-24*60-10), event(-24*60-20),
                event(-24*60-33), event(-24*60-45), event(-24*60-50), event(-1)]
        self.assertEqual(recurrent_incidents(rows,T0), ())

    def test_three_separate_even_within_two_days_not_clock_pattern(self):
        rows=[event(-15),event(-5*60),event(-24*60)]
        r=recurrent_incidents(rows,T0)
        self.assertEqual(len(r),1)
        self.assertIsNone(r[0].recurring_utc_hour)

    def test_invalid_event_types_ignored(self):
        rows=[event(-i*24*60) for i in range(3)] + [
            event(0,severity='warning'), event(0,title='SNMP опрос'),
            event(0,detail='noise 192.168.8.12'), event(0,detail='999.3.4.5'),
            ('not-iso','error','Устройство не отвечает', IP),
            ('2026-10-28T10:00:00','error','Устройство не отвечает',IP),
            ('2030-10-28T10:00:00+00:00','error','Устройство не отвечает',IP),
            ('2020-01-01T10:00:00+00:00','error','Устройство не отвечает',IP)]
        r=recurrent_incidents(rows,T0)
        self.assertEqual(len(r),1)
        self.assertEqual(r[0].episodes,3)

    def test_no_false_recurrence_from_other_severity_or_title(self):
        self.assertEqual(recurrent_incidents([event(-i*24*60,title='Устройство снова доступно') for i in range(3)],T0),())

    def test_utc_offset_is_normalized(self):
        rows=[event(at=(T0-timedelta(days=i)).astimezone(timezone(timedelta(hours=5)))) for i in range(3)]
        r=recurrent_incidents(rows,T0)
        self.assertEqual(len(r),1)
        self.assertEqual(r[0].recurring_utc_hour,10)

    def test_unaware_now_rejected(self):
        with self.assertRaises(ValueError):
            recurrent_incidents([],datetime(2026,10,28))

    def test_bounded_records_scope(self):
        rows=[event(0,severity='info')]*(MAX_ROWS+3) + [event(-i*24*60) for i in range(3)]
        self.assertEqual(recurrent_incidents(rows,T0),())

    def test_sorted_by_frequency_not_ip(self):
        rows=[event(-i*24*60,ip='10.0.0.2') for i in range(3)] + [event(-i*24*60,ip='10.0.0.3') for i in range(4)]
        self.assertEqual([x.ip for x in recurrent_incidents(rows,T0)],['10.0.0.3','10.0.0.2'])

    def test_finding_is_low_confidence_and_honest(self):
        fs=recurrence_findings([event(-24*60*i) for i in range(3)],T0)
        self.assertEqual(fs[0].code,'recurrent_no_icmp')
        self.assertEqual(fs[0].confidence,'низкая')
        self.assertIn('Нет доказательства',fs[0].interpretation)
        self.assertIn('локальной истории',fs[0].interpretation)


class HealthIndexTests(unittest.TestCase):
    def test_empty_and_insufficient(self):
        self.assertIsNone(availability_index({}).score)
        self.assertIsNone(availability_index({'192.168.1.1':'up'}).score)

    def test_reject_stale_or_unknown_and_invalid_ips(self):
        x=availability_index({'192.168.1.1':'up','192.168.1.2':'down',
                              '192.168.1.3':'up','192.168.1.4':'unknown',
                              'not-ip':'up'})
        self.assertEqual((x.responsive,x.unresponsive,x.score),(2,1,67))
        self.assertIn('НЕ оценка общей исправности',x.explanation)

    def test_zero_is_valid_only_after_enough_fresh_measurements(self):
        x=availability_index({f'10.0.0.{i}':'down' for i in range(1,4)})
        self.assertEqual(x.score,0)
        self.assertEqual(x.unresponsive,3)

    def test_private_and_public_ipv4_both_valid_metrics(self):
        x=availability_index({'8.8.8.8':'up','1.1.1.1':'up','10.0.0.1':'up'})
        self.assertEqual(x.score,100)

    def test_bounded_report_export_and_html_escapes(self):
        health=availability_index({'10.0.0.1':'up','10.0.0.2':'down','10.0.0.3':'up'})
        j=export_report((),health=health)
        self.assertEqual(j['icmp_index']['score'],67)
        self.assertEqual(j['engine'],'DETECTIVE rules v2.3')
        report=export_html_report((),health=health)
        self.assertIn('67/100',report)
        self.assertIn('Индекс ответов ICMP',report)
        self.assertNotIn('<script>',report)

    def test_missing_index_explicit_in_report(self):
        health=availability_index({})
        self.assertIsNone(export_report((),health=health)['icmp_index']['score'])
        self.assertIn('Не рассчитан',export_html_report((),health=health))


if __name__=='__main__':
    unittest.main()
