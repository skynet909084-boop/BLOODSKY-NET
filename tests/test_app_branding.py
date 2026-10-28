"""Tests for the original BLOODSKY NET Windows app icon."""
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch
from PIL import Image
from bloodsky_net.app_branding import set_window_icon
from tools.build_branding import generate_assets


class BrandingTests(unittest.TestCase):
    def test_ico_and_png_dimensions(self):
        with tempfile.TemporaryDirectory() as d:
            ico, png = generate_assets(Path(d))
            self.assertTrue(ico.exists())
            with Image.open(ico) as image:
                self.assertEqual(image.size, (256, 256))
            with Image.open(png) as image:
                self.assertEqual(image.size, (256, 256))

    def test_tk_window_icon_is_kept_alive(self):
        app = Mock()
        with patch('bloodsky_net.app_branding.ImageTk.PhotoImage') as photo:
            self.assertTrue(set_window_icon(app))
            app.iconphoto.assert_called_once_with(True, photo.return_value)
            self.assertIs(app._bloodsky_icon_ref, photo.return_value)

    def test_failure_does_not_prevent_launch(self):
        app = Mock()
        with patch('bloodsky_net.app_branding.ImageTk.PhotoImage', side_effect=RuntimeError('no display')):
            self.assertFalse(set_window_icon(app))

    def test_source_is_approved_icon_and_small_enough(self):
        from bloodsky_net.icon_source import WEBP_BASE64
        import base64
        self.assertTrue(WEBP_BASE64.startswith('UklG'))
        self.assertLess(len(base64.b64decode(WEBP_BASE64)), 16000)
