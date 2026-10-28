"""GUI smoke (virtual display) for manually labelled Wi-Fi survey series."""
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch
from bloodsky_net.storage import Storage
from bloodsky_net.ui import NetApp

with TemporaryDirectory() as td:
    with patch('bloodsky_net.ui.Storage',lambda: Storage(Path(td)/'gui.db')):
        app=NetApp()
        app.update_idletasks()
        app.show_page('Покрытие Wi-Fi')
        app.survey_series.set('Замена AP в офисе')
        for s in (30,35,75,80):
            app.store.save_wifi_survey_point('Этаж 1',25,25,'Office','AA:BB:CC:DD:EE:01',s,36,
                room='Зал',phase='До' if s<50 else 'После',series='Замена AP в офисе')
        app.store.save_wifi_survey_point('Этаж 1',25,25,'Guest','AA:BB:CC:DD:EE:02',90,36,
                room='Зал',phase='До',series='Другой визит')
        app._wifi_survey_refresh()
        assert len(app.survey_comparison.get_children())==1, 'Expected one same-series comparison'
        assert len(app.survey_stats.get_children())==2, 'Expected distinct before/after stats'
        assert len(app._survey_visible_points)==4, 'Failed to isolate series'
        report=app._wifi_survey_report_data()
        assert report['comparisons'][0]['delta_percentage_points']==45
        assert 'Guest' not in str(report)
        app.survey_series.set('Другой визит')
        app._wifi_survey_refresh()
        assert len(app.survey_comparison.get_children())==0
        assert len(app._survey_visible_points)==1
        app.shutdown()
print('Wi-Fi RADAR 2.3 GUI smoke passed')
