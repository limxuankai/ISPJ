# Step 1: Data Preparation
path = 'C:/Users/chewy/OneDrive/Documents/GitHub/ISPJ/wordfiles'
data = []
labels = []
for file in os.listdir(path):
    if file.endswith('.docx'):
        text = docx2txt.process(os.path.join(path, file))
        data.append(text)
        labels.append(file.split('_')[0])

# Step 2: Text Preprocessing
nltk.download('stopwords')
stop_words = set(stopwords.words('english'))
def preprocess(text):
    tokens = word_tokenize(text.lower())
    tokens = [token for token in tokens if token.isalpha() and token not in stop_words]
    return ' '.join(tokens)
data = [preprocess(text) for text in data]

# Step 3: Feature Extraction
vectorizer = CountVectorizer()
X = vectorizer.fit_transform(data)
y = pd.Series(labels)

# Step 4: Model Training
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
clf = MultinomialNB()
clf.fit(X_train, y_train)

# Step 5: Model Evaluation
y_pred = clf.predict(X_test)
accuracy = accuracy_score(y_test, y_pred)
print(f'Accuracy: {accuracy:.2f}')

# Step 6: Model Deployment
def classify_doc(path):
    text = docx2txt.process(path)
    text = preprocess(text)
    X = vectorizer.transform([text])
    y_pred = clf.predict(X)
    return y_pred[0]