"""Controlled local SecureMesh attack demonstrations (disposable identities)."""
import argparse
import json
from securemesh.attacks.scenarios import AttackRunner, SCENARIOS
from securemesh.config import Settings


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('scenario', nargs='?', choices=(*SCENARIOS, 'all'))
    parser.add_argument('--list', action='store_true')
    parser.add_argument('--device-id')
    parser.add_argument('--url', default='http://127.0.0.1:8000')
    args = parser.parse_args()
    if args.list:
        print('\n'.join((*SCENARIOS, 'all')))
        return
    if not args.scenario:
        parser.error('Choose a scenario or --list')
    runner = None
    try:
        runner = AttackRunner(Settings.from_env(), args.url)
        runner.transport.start()
        target = args.device_id or ('device-02' if args.scenario == 'revoked' else 'device-01')
        print(json.dumps([result.public() for result in runner.run(args.scenario, target)], indent=2))
    except Exception as exc:
        print(json.dumps({'observed_result': 'INCONCLUSIVE', 'reason': 'Scenario failed; check local services, disposable active identities and evidence preconditions.', 'failure_type': type(exc).__name__, 'scenario': getattr(runner, 'current_scenario', args.scenario)}))
        raise SystemExit(1)
    finally:
        if runner:
            runner.transport.stop()


if __name__ == '__main__':
    main()
