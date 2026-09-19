"""All trainable transforms live inside CV folds; sparse output stays bounded."""
from functools import lru_cache
import numpy as np
import pandas as pd
from scipy import sparse
from sklearn.base import BaseEstimator, TransformerMixin
from sklearn.compose import ColumnTransformer
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler
from src.features import url_features, header_features, content_features
from src.features.ai_text_features import TextSignals

@lru_cache(maxsize=6000)
def static_facts(subject, body_text, body_html, from_addr, reply_to, headers_json, urls, attachments):
    row = dict(subject=subject, body_text=body_text, body_html=body_html, from_addr=from_addr,
               reply_to=reply_to, headers_json=headers_json, urls=list(urls),
               attachments=[{"name": name, "ext": ext} for name, ext in attachments])
    return {**url_features.extract(row), **header_features.extract(row),
            **content_features.extract(row), "text": content_features.text(row)}

class AlertRows(BaseEstimator, TransformerMixin):
    def fit(self, X, y=None):
        self.fitted_ = True
        return self

    def transform(self, X):
        rows = X.to_dict("records") if isinstance(X, pd.DataFrame) else X
        return pd.DataFrame([static_facts(
            *(row.get(name, "") for name in ["subject", "body_text", "body_html", "from_addr", "reply_to"]),
            row.get("headers_json", "{}"), tuple(row.get("urls", [])),
            tuple((a["name"], a["ext"]) for a in row.get("attachments", []))) for row in rows])

NUMERIC = list(AlertRows().transform([{"subject": "", "body_text": "", "body_html": ""}]).drop(columns="text"))

class ToSparse(BaseEstimator, TransformerMixin):
    def fit(self, X, y=None):
        self.fitted_ = True
        return self
    def transform(self, X):
        return sparse.csr_matrix(X)
    def get_feature_names_out(self, input_features=None):
        return np.asarray(input_features, dtype=object)

def features():
    columns = ColumnTransformer([
        ("tfidf", TfidfVectorizer(ngram_range=(1, 2), max_features=20_000, sublinear_tf=True,
                                 strip_accents="unicode", dtype=np.float64), "text"),
        ("facts", StandardScaler(with_mean=False), NUMERIC),
        ("style", Pipeline([("signals", TextSignals()), ("scale", StandardScaler(with_mean=False))]), "text"),
    ], sparse_threshold=1.)
    return Pipeline([("rows", AlertRows()), ("columns", columns), ("sparse", ToSparse())])
