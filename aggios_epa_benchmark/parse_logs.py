# Quick and (very) dirty script to parse the logs and output values for the paper
from collections import defaultdict
import statistics


def time_str_to_float(time_str, ms=False):
    factor = 1.
    if ms:
        factor = 1_000
    time_str = time_str.strip()
    if time_str[-2:] == 'ns':
        return float(time_str[:-2]) / 1_000_000_000. * factor
    if time_str[-2:] == 'µs':
        return float(time_str[:-2]) / 1_000_000. * factor
    if time_str[-2:] == 'ms':
        return float(time_str[:-2]) / 1_000. * factor
    return float(time_str[:-1]) * factor


def print_avg_in_tables(results, entry):
    n_range = results.keys()
    print('  & $' + '$ & $'.join(n_range) + '$ \\\\')

    k_values = results[list(results.keys())[0]].keys()

    for k in k_values:
        # print(str(k) + ' & ' + ' & '.join([str(round(statistics.mean(results[n][k][entry]), 2)) + ' (' + str(round(statistics.pstdev(results[n][k][entry]), 2)) + ') ' for n in n_range]) + ' \\\\')
        print(str(k) + ' & ' + ' & '.join([f'{statistics.mean(results[n][k][entry]):.3f}' for n in n_range]) + ' \\\\')


def print_for_plot(results, k_values, entry):
    for k in k_values:
        print('\\addplot coordinates {')
        for n in results.keys():
            print(f'({n.strip()[2:]}, {results[n][k][entry]:.3f})')
        print('};')
        print(f'\\addlegendentry{{$k={k}$}}')


def percentage_value(value):
    if value < 1:
        return '<1'
    return '{:.0f}'.format(round(value, 0))


def print_percentage_in_table(compact, k_value):
    n_range = compact.keys()
    k = k_value
    print('  & $' + '$ & $'.join(n_range) + '$ \\\\')

    for entry in ['$P_{{1, j}}$', '$P_{{2, j}}$', 'Commit R1', 'Commit R2', 'Other']:
        percentage = compact[n][k][entry] / compact[n][k]['prover_time'] * 100
        if percentage < 1:
            value = percentage_value(compact[n][k][entry] / compact[n][k]['prover_time'] * 100)
            print(f'{entry} & ' + ' & '.join([f'{value}\\%' for n in n_range]) + ' \\\\')

        value = percentage_value(compact[n][k][entry] / compact[n][k]['prover_time'] * 100)
        print(f'{entry} & ' + ' & '.join([f'{value}\\%' for n in n_range]) + ' \\\\')


def print_for_plot_percent(compact, k_value):
    for entry in ['$P_{{1, j}}$', '$P_{{2, j}}$', 'Commit R1', 'Commit R2', 'Other']:
        print('\\addplot coordinates {')
        for n in compact.keys():
            value = round(compact[n][k_value][entry] / float(compact[n][k_value]['prover_time']) * 100, 3)
            print(f'({n[2:]}, {value:.3f})')
        print('};')
        print(f'\\addlegendentry{{{entry}}}')


with open('log.txt', 'r', encoding='utf-8') as f:
    lines = f.readlines()

results = defaultdict(lambda: defaultdict(lambda: defaultdict(int)))

i = 0
total_time = 0
while i < len(lines):
    if lines[i][0] == '#':
        n = lines[i].split('###')[1].split(' = ')[1]

    elif lines[i][0] == '=':
        k = int(lines[i].split('===')[1].split(' = ')[1])
        results[n][k]['prover_time'] = []
        results[n][k]['verif_time'] = []
        results[n][k]['$P_{{1, j}}$'] = []
        results[n][k]['$P_{{2, j}}$'] = []
        results[n][k]['Commit R1'] = []
        results[n][k]['Commit R2'] = []

    elif lines[i][0] == '-':
        results[n][k]['prover_time'].append(time_str_to_float(lines[i + 38].split('took')[1]))
        results[n][k]['verif_time'].append(time_str_to_float(lines[i + 46].split('took')[1]))
        results[n][k]['$P_{{1, j}}$'].append(time_str_to_float(lines[i + 17].split('took')[1]))
        results[n][k]['$P_{{2, j}}$'].append(time_str_to_float(lines[i + 18].split('took')[1]))
        # results[n][k]['Commit R1'].append(time_str_to_float(lines[i + 23].split('Took')[1]))
        results[n][k]['Commit R1'].append(time_str_to_float(lines[i + 33].split('Took')[1]))
        # results[n][k]['Commit R2'].append(time_str_to_float(lines[i + 27].split('Took')[1]))
        results[n][k]['Commit R2'].append(time_str_to_float(lines[i + 37].split('Took')[1]))

        total_time += time_str_to_float(lines[i + 38].split('took')[1]) + time_str_to_float(lines[i + 46].split('took')[1])

        # i += 36
        i += 47
    i += 1


print('prover time (s), table')
print_avg_in_tables(results, 'prover_time')
print('\n \n ============ \n \n')
print('verifier time (s), table')
print_avg_in_tables(results, 'verif_time')
print(f'\nTotal benchmark time (without setting up of public params): {total_time}s')
results_compact = {n: {k: {entry: statistics.mean(results[n][k][entry]) for entry in results[n][k].keys()} for k in results[n].keys()} for n in results.keys()}

for n in results_compact.keys():
    for k in results_compact[n].keys():
        results_compact[n][k]['Other'] = results_compact[n][k]['prover_time'] - results_compact[n][k]['$P_{{1, j}}$'] - results_compact[n][k]['$P_{{2, j}}$'] - results_compact[n][k]['Commit R1'] - results_compact[n][k]['Commit R2']

print('\n\n\n\n Computation of prover time (graph)')
print_for_plot(results_compact, [2, 5, 10, 50, 100], 'prover_time')

print('\n\n\n\n Computation of verifier time (graph)')
print_for_plot(results_compact, [2, 5, 10, 50, 100], 'verif_time')


print('\n\n\n\n\n Computation of bottlenecks for k=10 (table)')


print_percentage_in_table(results_compact, 10)

print('\n\n\n\n\n Computation of bottlenecks for k=10 (graph)')
print_for_plot_percent(results_compact, 10)



print('\n\n\n\n\n Computation of bottlenecks for k=100 (table)')


print_percentage_in_table(results_compact, 100)

print('\n\n\n\n\n Computation of bottlenecks for k=100 (graph)')
print_for_plot_percent(results_compact, 100)
