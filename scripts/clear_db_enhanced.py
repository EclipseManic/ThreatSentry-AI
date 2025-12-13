"""scripts/clear_db_enhanced.py
Safer DB maintenance for the Threat Sentric AI dashboard.

Features:
 - Dry-run summary by default
 - Flags to clear devices and/or vulnerabilities
 - Option to reset `notified` flags instead of deleting rows
 - Preserves trained model file by default; use --delete-model to remove it
 - Explicit confirmations unless --yes is supplied

Usage (PowerShell):
 & "./.venv/Scripts/python.exe" scripts/clear_db_enhanced.py --help
"""
import sys
import pathlib
# Ensure project root is on sys.path so `from data import ...` works when run from scripts/
PROJECT_ROOT = pathlib.Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))
import argparse
import os
from data import get_session, Device, Vulnerability, init_db
from core import get_logger
from core.config import MODEL_PATH

logger = get_logger('scripts.clear_db_enhanced')


def confirm(prompt: str) -> bool:
    ans = input(f"{prompt} [y/N]: ")
    return ans.strip().lower() in ('y', 'yes')


def main():
    parser = argparse.ArgumentParser(description='Enhanced DB cleanup for the Threat Sentric AI dashboard.')
    parser.add_argument('--yes', action='store_true', help='Perform actions without interactive confirmation.')
    parser.add_argument('--delete-devices', action='store_true', help='Delete Device rows from DB.')
    parser.add_argument('--delete-vulns', action='store_true', help='Delete Vulnerability rows from DB.')
    parser.add_argument('--reset-notified', action='store_true', help='Reset notified flags (set notified = False) instead of deleting rows.')
    parser.add_argument('--delete-model', action='store_true', help='Also delete trained model file at MODEL_PATH (default: do not delete).')
    args = parser.parse_args()

    engine = init_db()
    session = get_session()
    try:
        total_devices = session.query(Device).count()
        total_vulns = session.query(Vulnerability).count()
        print(f"DB summary: {total_devices} devices, {total_vulns} vulnerabilities.")

        # Determine planned actions
        planned = []
        if args.delete_devices:
            planned.append('Delete all Device rows')
        if args.delete_vulns:
            planned.append('Delete all Vulnerability rows')
        if args.reset_notified:
            planned.append('Reset "notified" flag on all devices')
        if args.delete_model:
            planned.append(f'Delete model file at {MODEL_PATH}')

        if not planned:
            print('No action specified. Use --delete-devices, --delete-vulns, or --reset-notified. Exiting.')
            return

        print('Planned actions:')
        for p in planned:
            print(' -', p)

        if not args.yes:
            if not confirm('Proceed with these actions?'):
                print('Aborted by user.')
                return

        # Execute actions
        if args.reset_notified:
            print('Resetting notified flags...')
            session.query(Device).update({Device.notified: False})
            session.commit()
            logger.info('Reset notified flags for %d devices.', total_devices)
            print('Notified flags reset.')

        if args.delete_vulns:
            print('Deleting vulnerabilities...')
            session.query(Vulnerability).delete()
            session.commit()
            logger.info('Deleted %d vulnerabilities.', total_vulns)
            print('Vulnerabilities deleted.')

        if args.delete_devices:
            print('Deleting devices...')
            session.query(Device).delete()
            session.commit()
            logger.info('Deleted %d devices.', total_devices)
            print('Devices deleted.')

        if args.delete_model:
            if MODEL_PATH and os.path.exists(MODEL_PATH):
                if not args.yes:
                    if confirm(f'Delete model file at {MODEL_PATH}?'):
                        os.remove(MODEL_PATH)
                        print('Model file deleted.')
                else:
                    os.remove(MODEL_PATH)
                    print('Model file deleted.')
            else:
                print('No model file found to delete.')

        print('Completed requested actions.')
    except Exception as e:
        session.rollback()
        logger.exception('Failed to perform requested actions: %s', e)
        print('Error:', e)
    finally:
        session.close()


if __name__ == '__main__':
    main()
