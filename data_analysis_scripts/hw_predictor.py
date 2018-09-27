import pandas as pd
import matplotlib.pyplot as plt
import numpy as np


def get_throughput_prediction(df, path):

    #filter on wifi subflow
    filtered_df = df[df['interface'] == 'wifi']
    print "Get Throughput Prediction on wifi"
    get_throughput_prediction_subflow(filtered_df, path, "wifi")

    # filter on lte subflow
    filtered_df = df[df['interface'] == 'lte']
    print "Get Throughput Prediction on lte"
    get_throughput_prediction_subflow(filtered_df, path, "lte")

def get_throughput_prediction_subflow(df, path, interface):

    plt.figure(figsize=(20, 10))

    #generate an array of per-packet throughput values
    x_array = np.array(df['time_offset'])
    y_array = np.array(df['total_bytes'])

    x_val = []
    series = []
    initial_timestamp = float(x_array[0])
    bytes_sent = float(y_array[0])/float(1000)
    for i in range(1,len(x_array)):
        current_timestamp = float(x_array[i])
        if(current_timestamp - initial_timestamp > 0.05):
            series.append(float(bytes_sent)/float(current_timestamp-initial_timestamp))
            x_val.append(current_timestamp)
            initial_timestamp = current_timestamp
            bytes_sent = float(y_array[i])/float(1000)
        else:
            bytes_sent += (float(y_array[i])/float(1000))

    plt.plot(x_val,series, label='observed', linestyle='-')
    plt.title("Throughput "+interface)
    plt.xlabel('Time offset')
    plt.ylabel('KB/sec')
    plt.legend()
    plt.savefig(path + "throughput_"+interface+".png", dpi=400, bbox_inches='tight')
    plt.clf()

    #get estimated throughput value
    estimated_series = double_exponential_smoothing(series, 0.8, 0.2)

    # abs_diff = []
    diff = []
    for i in range(0,len(series)):
        if(estimated_series[i] > 187.5):
            print "Predicted throughput of 1500 kbps by "+str(int(x_val[i] - x_val[0]))
        # abs_diff.append(abs(series[i] - estimated_series[i]))
        diff.append(estimated_series[i] - series[i])

    #plot estimated vs. predicted throughput
    plt.scatter(x_val, series, label='observed', s=10, marker="*")
    plt.scatter(x_val, estimated_series[:-1], label='predicted', s=10, marker ="^")
    plt.title("Estimated vs. Predicted on "+interface+" subflow")
    plt.xlabel('Time offset')
    plt.ylabel('KB/sec')
    plt.legend()
    plt.savefig(path + "estimated_vs_predicted_"+interface+".png", dpi=400, bbox_inches='tight')
    plt.clf()

    plt.plot(x_val, diff, label='abs_diff', linestyle = '-')
    plt.title("Predicted - Real on "+interface+" subflow")
    plt.xlabel('Time offset')
    plt.ylabel('KB/sec')
    plt.legend()
    plt.savefig(path+ "error_"+interface+".png", dpi=400,bbox_inches='tight')
    plt.clf()

def double_exponential_smoothing(series, alpha, beta):

    result = [series[0]]
    for n in range(1, len(series)+1):
        if n==1:
            level, trend = series[0], series[1] - series[0]
        if n>= len(series):
            value = result[-1]
        else:
            value = series[n]
        last_level, level = level, alpha*value + (1-alpha)*(level+trend)
        trend = beta*(level-last_level) + (1-beta)*trend
        estimate = level + trend
        if (estimate < 0):
            estimate = 0
        result.append(estimate)
    return result

def hw_estimation(series, last_level, last_trend, alpha, beta):

    #Initialize level, trend, and estimate
    level = -1
    trend = -1
    estimate = -1

    if(len(series) == 1):
        return series[0], level, trend
    #if first estimation -- set the first value of level and trend
    if(len(series) == 2):
        level, trend = series[0], series[1] - series[0]

    value = series[len(series)-1]
    last_level, level = level, alpha * value + (1 - alpha) * (level + trend)
    trend = beta * (level - last_level) + (1 - beta) * trend

    estimate = level + trend
    return estimate, level, trend
