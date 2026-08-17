#!/bin/bash -l
#SBATCH --job-name=witfoo-toy-ingest
#SBATCH --time=0:30:00
#SBATCH --partition=short
#SBATCH --nodes=1
#SBATCH --ntasks=1
#SBATCH --cpus-per-task=4
#SBATCH --mem=16GB
#SBATCH --gres=gpu:h100_1g.10gb
module load Miniforge3/24.11.3-0
source ~/.bashrc
conda activate pids
export LD_LIBRARY_PATH=$CONDA_PREFIX/lib:$LD_LIBRARY_PATH
cd ~/PIDSMaker/scripts/apptainer
make up
cd ~/PIDSMaker
./WitFooParsing/load_witfoo_db.sh witfoo_toy $HOME/PIDSMaker/WitFooParsing/toy_B_v3/
python pidsmaker/main.py orthrus WITFOO_TOY \
    --construction.time_window_size=600.0 \
    --featurization.emb_dim=32 --featurization.epochs=2 \
    --restart_from_scratch --database_host localhost --artifact_dir ./artifacts/
