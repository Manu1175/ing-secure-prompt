import os
import glob
import re
import torch
import pandas as pd
from sklearn.model_selection import train_test_split
from torch.utils.data import Dataset
from transformers import BertTokenizerFast, BertForTokenClassification, Trainer, TrainingArguments
from difflib import SequenceMatcher

# ---- 1️⃣ Load Excel Data from prompts/ folder ----
data_folder = os.path.join(os.path.dirname(__file__), "../prompts")
excel_files = glob.glob(os.path.join(data_folder, "*.xlsx*"))

dfs = []
for file in excel_files:
    try:
        df = pd.read_excel(file)
        print(f"Loaded {file} with {len(df)} rows.")
        dfs.append(df)
    except Exception as e:
        print(f"❌ Failed to read {file}: {e}")

if not dfs:
    raise ValueError("No Excel files found in prompts/ folder.")

df = pd.concat(dfs, ignore_index=True)
df = df.dropna(subset=["Prompt", "Sanitized Prompt"])
print("✅ Total samples loaded:", len(df))

originals = df["Prompt"].tolist()
sanitized = df["Sanitized Prompt"].tolist()

# ---- 2️⃣ Detect placeholders ----
placeholder_pattern = re.compile(r"<([A-Z0-9_]+)>")
placeholders = sorted(list({ph for s in sanitized for ph in placeholder_pattern.findall(s)}))
print("📘 Placeholders detected:", placeholders)

# ---- 3️⃣ Create label mapping ----
label_list = ["O"]
for ph in placeholders:
    label_list.append(f"B-{ph}")
    label_list.append(f"I-{ph}")
label2id = {l: i for i, l in enumerate(label_list)}
id2label = {i: l for l, i in label2id.items()}
print(f"🧾 Label set size: {len(label_list)}")

# ---- 4️⃣ Tokenizer ----
tokenizer = BertTokenizerFast.from_pretrained("bert-base-cased")

# ---- 5️⃣ Token-level alignment function ----
def align_labels(original, sanitized):
    """Align original text tokens to sanitized text placeholders."""
    tokens = tokenizer.tokenize(original)
    labels = ["O"] * len(tokens)

    # find where placeholders occur in sanitized
    for match in re.finditer(r"<([A-Z0-9_]+)>", sanitized):
        ph = match.group(1)
        ph_tag = match.group(0)

        # Get text parts before and after placeholder
        before = sanitized[: match.start()]
        after = sanitized[match.end():]

        # Use SequenceMatcher to find what text in original was replaced
        sm = SequenceMatcher(None, original, before)
        before_end = sm.find_longest_match(0, len(original), 0, len(before)).size
        start = before_end
        # estimate end of replaced span
        end = min(len(original), start + 25)  # just limit search window

        # Tokenize up to that region
        offsets = tokenizer(original, return_offsets_mapping=True, add_special_tokens=False)["offset_mapping"]

        for i, (s, e) in enumerate(offsets):
            if s >= start and s < end:
                labels[i] = f"B-{ph}" if labels[i] == "O" else f"I-{ph}"

    return [label2id[l] for l in labels]


# ---- 6️⃣ Encode prompts and generate labels ----
encodings = tokenizer(
    originals,
    padding=True,
    truncation=True,
    max_length=256,
    return_tensors="pt",
    is_split_into_words=False,
)

labels = []
max_len = encodings["input_ids"].shape[1]

for o, s in zip(originals, sanitized):
    l = align_labels(o, s)
    l = l + [0] * (max_len - len(l))
    l = l[:max_len]
    labels.append(l)

labels = torch.tensor(labels)

# ---- 7️⃣ Dataset split ----
train_idx, val_idx = train_test_split(range(len(originals)), test_size=0.1, random_state=42)

class PromptDataset(Dataset):
    def __init__(self, encodings, labels, indices):
        self.encodings = {k: v[indices] for k, v in encodings.items()}
        self.labels = labels[indices]

    def __getitem__(self, idx):
        item = {key: val[idx] for key, val in self.encodings.items()}
        item["labels"] = self.labels[idx]
        return item

    def __len__(self):
        return len(self.labels)

train_dataset = PromptDataset(encodings, labels, train_idx)
val_dataset = PromptDataset(encodings, labels, val_idx)

# ---- 8️⃣ Model ----
model = BertForTokenClassification.from_pretrained(
    "bert-base-cased",
    num_labels=len(label_list),
    id2label=id2label,
    label2id=label2id
)

# ---- 9️⃣ Training setup ----
training_args = TrainingArguments(
    output_dir="./placeholder_model",
    eval_strategy="epoch",
    save_strategy="epoch",
    do_eval=True,
    learning_rate=2e-5,
    per_device_train_batch_size=4,
    per_device_eval_batch_size=4,
    num_train_epochs=3,
    weight_decay=0.01,
    logging_dir="./logs",
    logging_steps=10,
    report_to="tensorboard",
)

trainer = Trainer(
    model=model,
    args=training_args,
    train_dataset=train_dataset,
    eval_dataset=val_dataset,
)

# ---- 🔟 Train model ----
trainer.train()

# ---- 1️⃣1️⃣ Save model and tokenizer ----
os.makedirs("./placeholder_model", exist_ok=True)
model.save_pretrained("./placeholder_model")
tokenizer.save_pretrained("./placeholder_model")

print("✅ Multi-class NER model saved to ./placeholder_model")
