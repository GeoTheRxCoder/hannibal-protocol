using Hannibal.Contracts;

namespace Hannibal.Overwatch;

/// <summary>
/// Scoring only. A signed model loader MUST validate the artifact, feature
/// schema, dimensions, and publisher trust before use.
/// </summary>
public sealed class KMeansAnomalyScorer : IAnomalyScorer
{
    private readonly string _modelId;
    private readonly double[] _caps, _mean, _scale, _thresholds;
    private readonly double[][] _centroids;
    private readonly double _minimumCoverage;

    public KMeansAnomalyScorer(string modelId, double[] caps,
        double[] mean, double[] scale, double[][] centroids,
        double[] thresholds, double minimumCoverage = .90)
    {
        if (string.IsNullOrWhiteSpace(modelId) || caps.Length == 0 ||
            mean.Length != caps.Length || scale.Length != caps.Length ||
            centroids.Length == 0 || thresholds.Length != centroids.Length ||
            centroids.Any(c => c.Length != caps.Length) ||
            scale.Any(s => s <= 0 || !double.IsFinite(s)) ||
            caps.Any(v => v < 0 || !double.IsFinite(v)) ||
            mean.Any(v => !double.IsFinite(v)) ||
            thresholds.Any(t => t <= 0 || !double.IsFinite(t)) ||
            centroids.Any(c => c.Any(v => !double.IsFinite(v))))
            throw new ArgumentException("Invalid candidate model dimensions/values.");
        if (minimumCoverage < 0 || minimumCoverage > 1)
            throw new ArgumentOutOfRangeException(nameof(minimumCoverage));
        _modelId=modelId;
        _caps=(double[])caps.Clone();
        _mean=(double[])mean.Clone();
        _scale=(double[])scale.Clone();
        _centroids=centroids.Select(c => (double[])c.Clone()).ToArray();
        _thresholds=(double[])thresholds.Clone();
        _minimumCoverage=minimumCoverage;
    }

    public ModelScore Score(ReadOnlySpan<double> rawFeatures, double coverage)
    {
        if (!double.IsFinite(coverage) || coverage < _minimumCoverage ||
            rawFeatures.Length != _caps.Length)
            return Unscorable(coverage);

        var z = new double[_caps.Length];
        int exceeded = 0;
        for(int i=0;i<rawFeatures.Length;i++)
        {
            double v=rawFeatures[i];
            if (!double.IsFinite(v) || v < 0) return Unscorable(coverage);
            if (v > _caps[i]) exceeded++;
            z[i]=(Math.Log(1.0 + Math.Min(v, _caps[i])) - _mean[i])/_scale[i];
        }
        int bestCluster=-1;
        double bestDistance=double.PositiveInfinity;
        for(int c=0;c<_centroids.Length;c++)
        {
            double squared=0;
            for(int f=0;f<z.Length;f++)
            {
                double delta=z[f]-_centroids[c][f];
                squared+=delta*delta;
            }
            double distance=Math.Sqrt(squared);
            if (distance < bestDistance)
            {
                bestCluster=c;
                bestDistance=distance;
            }
        }
        double threshold=_thresholds[bestCluster];
        return new ModelScore(_modelId,bestCluster,bestDistance,
            threshold,bestDistance/threshold,coverage,true,exceeded);
    }

    private ModelScore Unscorable(double coverage) =>
        new(_modelId,-1,double.NaN,double.NaN,double.NaN,coverage,false);
}
