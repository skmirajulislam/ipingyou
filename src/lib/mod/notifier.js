/**
 * ============================================================
 *  Native OS Desktop Notifier
 * ============================================================
 *  Zero-dependency cross-platform desktop notifications.
 *  Uses OS-native tools (osascript, notify-send, powershell).
 * ============================================================
 */

import { execa } from 'execa';

/**
 * Send a native desktop notification.
 * @param {string} title 
 * @param {string} message 
 * @returns {Promise<boolean>}
 */
export async function notifyDesktop(title, message) {
  // Emit terminal bell alert
  try { process.stdout.write('\u0007'); } catch {}

  const platform = process.platform;
  const cleanTitle = String(title || 'iPingYou').replace(/["'\\`$]/g, '');
  const cleanMsg = String(message || '').replace(/["'\\`$]/g, '');

  try {
    if (platform === 'darwin') {
      await execa('osascript', [
        '-e',
        `display notification "${cleanMsg}" with title "${cleanTitle}"`
      ], { reject: false, timeout: 3000 });
      return true;
    }

    if (platform === 'linux') {
      await execa('notify-send', [cleanTitle, cleanMsg], { reject: false, timeout: 3000 });
      return true;
    }

    if (platform === 'win32') {
      const script = `
        [Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime] | Out-Null
        $template = [Windows.UI.Notifications.ToastNotificationManager]::GetTemplateContent([Windows.UI.Notifications.ToastTemplateType]::ToastText02)
        $textNodes = $template.GetElementsByTagName("text")
        $textNodes.Item(0).AppendChild($template.CreateTextNode("${cleanTitle}")) | Out-Null
        $textNodes.Item(1).AppendChild($template.CreateTextNode("${cleanMsg}")) | Out-Null
        $notifier = [Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier("iPingYou")
        $notification = [Windows.UI.Notifications.ToastNotification]::new($template)
        $notifier.Show($notification)
      `;
      await execa('powershell', ['-NoProfile', '-ExecutionPolicy', 'Bypass', '-Command', script], { reject: false, timeout: 4000 });
      return true;
    }
  } catch {
    return false;
  }

  return false;
}
