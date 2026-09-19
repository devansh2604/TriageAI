"""Bounded dense projection for the histogram boosting candidate."""
from sklearn.decomposition import TruncatedSVD

class BoundedSVD(TruncatedSVD):
    """Dense HGB receives at most 64 latent features, never a dense 20k matrix."""
    def fit_transform(self, X, y=None):
        self.n_components = min(self.n_components, max(1, X.shape[1]-1))
        return super().fit_transform(X, y)
