import os
import win32con
import win32gui


def show_message_dialog(
        title="Message",
        message="CHANGE_ME"
):
    win32gui.MessageBox(0, message, title, win32con.MB_OK)


def open_file_dialog(
        default_filename='Game',
        default_fileext='exe',
        title='Open file',
        file_filter='Any file\0*.*\0',
        custom_filter='Other file types\0*.*\0',
        init_dir=os.environ['temp'],
        flags=win32con.OFN_EXPLORER
):
    # file_filter = 'Python Scripts\0*.py;*.pyw;*.pys\0Text files\0*.txt\0'
    # custom_filter = 'Other file types\0*.*\0'
    try:
        file_name, custom_filter, out_flags = win32gui.GetOpenFileNameW(
            InitialDir=init_dir,
            Flags=flags,
            File=default_filename, DefExt=default_fileext,
            Title=title,
            Filter=file_filter,
            FilterIndex=0)
    except Exception:
        return None

    return file_name
